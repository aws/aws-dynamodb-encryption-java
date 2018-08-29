/*
 * Copyright 2015 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"). You may not use this file except
 * in compliance with the License. A copy of the License is located at
 *
 * http://aws.amazon.com/apache2.0
 *
 * or in the "license" file accompanying this file. This file is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */
package com.amazonaws.services.dynamodbv2.datamodeling.encryption.providers.store;

import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import com.amazonaws.AmazonClientException;
import com.amazonaws.services.dynamodbv2.AmazonDynamoDB;
import com.amazonaws.services.dynamodbv2.datamodeling.encryption.DynamoDBEncryptor;
import com.amazonaws.services.dynamodbv2.datamodeling.encryption.EncryptionContext;
import com.amazonaws.services.dynamodbv2.datamodeling.encryption.providers.EncryptionMaterialsProvider;
import com.amazonaws.services.dynamodbv2.datamodeling.encryption.providers.WrappedMaterialsProvider;
import com.amazonaws.services.dynamodbv2.datamodeling.internal.Utils;
import com.amazonaws.services.dynamodbv2.model.AttributeDefinition;
import com.amazonaws.services.dynamodbv2.model.AttributeValue;
import com.amazonaws.services.dynamodbv2.model.ComparisonOperator;
import com.amazonaws.services.dynamodbv2.model.Condition;
import com.amazonaws.services.dynamodbv2.model.ConditionalCheckFailedException;
import com.amazonaws.services.dynamodbv2.model.CreateTableResult;
import com.amazonaws.services.dynamodbv2.model.ExpectedAttributeValue;
import com.amazonaws.services.dynamodbv2.model.GetItemRequest;
import com.amazonaws.services.dynamodbv2.model.KeySchemaElement;
import com.amazonaws.services.dynamodbv2.model.KeyType;
import com.amazonaws.services.dynamodbv2.model.ProvisionedThroughput;
import com.amazonaws.services.dynamodbv2.model.PutItemRequest;
import com.amazonaws.services.dynamodbv2.model.QueryRequest;
import com.amazonaws.services.dynamodbv2.model.ScalarAttributeType;

/**
 * Provides a simple collection of EncryptionMaterialProviders backed by an encrypted DynamoDB
 * table. This can be used to build key hierarchies or meta providers.
 *
 * Currently, this only supports AES-256 in AESWrap mode and HmacSHA256 for the providers persisted
 * in the table.
 *
 * @author rubin
 */
public class MetaStore extends ProviderStore {
    private static final String INTEGRITY_ALGORITHM_FIELD = "intAlg";
    private static final String INTEGRITY_KEY_FIELD = "int";
    private static final String ENCRYPTION_ALGORITHM_FIELD = "encAlg";
    private static final String ENCRYPTION_KEY_FIELD = "enc";
    private static final Pattern COMBINED_PATTERN = Pattern.compile("([^#]+)#(\\d*)");
    private static final String DEFAULT_INTEGRITY = "HmacSHA256";
    private static final String DEFAULT_ENCRYPTION = "AES";
    private static final String MATERIAL_TYPE_VERSION = "t";
    private static final String META_ID = "amzn-ddb-meta-id";

    private static final String DEFAULT_HASH_KEY = "N";
    private static final String DEFAULT_RANGE_KEY = "V";

    private final Map<String, ExpectedAttributeValue> doesNotExist;
    private final String tableName;
    private final AmazonDynamoDB ddb;
    private final DynamoDBEncryptor encryptor;
    private final EncryptionContext ddbCtx;

    public MetaStore(final AmazonDynamoDB ddb, final String tableName,
            final DynamoDBEncryptor encryptor) {
        this.ddb = checkNotNull(ddb, "ddb must not be null");
        this.tableName = checkNotNull(tableName, "tableName must not be null");
        this.encryptor = checkNotNull(encryptor, "encryptor must not be null");

        ddbCtx = new EncryptionContext.Builder().withTableName(this.tableName)
                .withHashKeyName(DEFAULT_HASH_KEY).withRangeKeyName(DEFAULT_RANGE_KEY).build();

        final Map<String, ExpectedAttributeValue> tmpExpected = new HashMap<String, ExpectedAttributeValue>();
        tmpExpected.put(DEFAULT_HASH_KEY, new ExpectedAttributeValue().withExists(false));
        tmpExpected.put(DEFAULT_RANGE_KEY, new ExpectedAttributeValue().withExists(false));
        doesNotExist = Collections.unmodifiableMap(tmpExpected);
    }

    @Override
    public EncryptionMaterialsProvider getProvider(final String materialName, final long version) {
        final Map<String, AttributeValue> ddbKey = new HashMap<String, AttributeValue>();
        ddbKey.put(DEFAULT_HASH_KEY, new AttributeValue().withS(materialName));
        ddbKey.put(DEFAULT_RANGE_KEY, new AttributeValue().withN(Long.toString(version)));
        final Map<String, AttributeValue> item = ddbGet(ddbKey);
        if (item == null || item.isEmpty()) {
            throw new IndexOutOfBoundsException("No material found: " + materialName + "#" + version);
        }
        return decryptProvider(item);
    }

    @Override
    public EncryptionMaterialsProvider getOrCreate(final String materialName, final long nextId) {
        final SecretKeySpec encryptionKey = new SecretKeySpec(Utils.getRandom(32), DEFAULT_ENCRYPTION);
        final SecretKeySpec integrityKey = new SecretKeySpec(Utils.getRandom(32), DEFAULT_INTEGRITY);
        final Map<String, AttributeValue> ciphertext = conditionalPut(encryptKeys(materialName,
                nextId, encryptionKey, integrityKey));
        return decryptProvider(ciphertext);
    }

    @Override
    public long getMaxVersion(final String materialName) {
        final List<Map<String, AttributeValue>> items = ddb.query(
                new QueryRequest()
                .withTableName(tableName)
                .withConsistentRead(Boolean.TRUE)
                .withKeyConditions(
                        Collections.singletonMap(
                                DEFAULT_HASH_KEY,
                                new Condition().withComparisonOperator(
                                        ComparisonOperator.EQ).withAttributeValueList(
                                                new AttributeValue().withS(materialName))))
                                                .withLimit(1).withScanIndexForward(false)
                                                .withAttributesToGet(DEFAULT_RANGE_KEY)).getItems();
        if (items.isEmpty()) {
            return -1L;
        } else {
            return Long.parseLong(items.get(0).get(DEFAULT_RANGE_KEY).getN());
        }
    }

    @Override
    public long getVersionFromMaterialDescription(final Map<String, String> description) {
        final Matcher m = COMBINED_PATTERN.matcher(description.get(META_ID));
        if (m.matches()) {
            return Long.parseLong(m.group(2));
        } else {
            throw new IllegalArgumentException("No meta id found");
        }
    }

    /**
     * This API retrieves the intermediate keys from the source region and replicates it in the target region.
     * @param materialName
     * @param version
     * @param targetMetaStore
     */
    public void replicate(final String materialName, final long version, final MetaStore targetMetaStore) {
        try {
            final Map<String, AttributeValue> ddbKey = new HashMap<String, AttributeValue>();
            ddbKey.put(DEFAULT_HASH_KEY, new AttributeValue().withS(materialName));
            ddbKey.put(DEFAULT_RANGE_KEY, new AttributeValue().withN(Long.toString(version)));
            final Map<String, AttributeValue> item = ddbGet(ddbKey);
            if (item == null || item.isEmpty()) {
                throw new IndexOutOfBoundsException("No material found: " + materialName + "#" + version);
            }

            final Map<String, AttributeValue> plainText = getPlainText(item);
            final Map<String, AttributeValue> encryptedText = targetMetaStore.getEncryptedText(plainText);
            final PutItemRequest put = new PutItemRequest().withTableName(targetMetaStore.tableName).withItem(encryptedText)
                    .withExpected(doesNotExist);
            targetMetaStore.ddb.putItem(put);
        } catch (ConditionalCheckFailedException e) {
            //Item already present.
        }
    }
    /**
     * Creates a DynamoDB Table with the correct properties to be used with a ProviderStore.
     */
    public static CreateTableResult createTable(final AmazonDynamoDB ddb, final String tableName,
            final ProvisionedThroughput provisionedThroughput) {
        return ddb.createTable(Arrays.asList(new AttributeDefinition(DEFAULT_HASH_KEY,
                ScalarAttributeType.S), new AttributeDefinition(DEFAULT_RANGE_KEY,
                        ScalarAttributeType.N)), tableName, Arrays.asList(new KeySchemaElement(
                                DEFAULT_HASH_KEY, KeyType.HASH), new KeySchemaElement(DEFAULT_RANGE_KEY,
                                        KeyType.RANGE)), provisionedThroughput);

    }

    private Map<String, AttributeValue> conditionalPut(final Map<String, AttributeValue> item) {
        try {
            final PutItemRequest put = new PutItemRequest().withTableName(tableName).withItem(item)
                    .withExpected(doesNotExist);
            ddb.putItem(put);
            return item;
        } catch (final ConditionalCheckFailedException ex) {
            final Map<String, AttributeValue> ddbKey = new HashMap<String, AttributeValue>();
            ddbKey.put(DEFAULT_HASH_KEY, item.get(DEFAULT_HASH_KEY));
            ddbKey.put(DEFAULT_RANGE_KEY, item.get(DEFAULT_RANGE_KEY));
            return ddbGet(ddbKey);
        }
    }

    private Map<String, AttributeValue> ddbGet(final Map<String, AttributeValue> ddbKey) {
        return ddb.getItem(
                new GetItemRequest().withTableName(tableName).withConsistentRead(true)
                .withKey(ddbKey)).getItem();
    }

    private Map<String, AttributeValue> encryptKeys(final String name, final long version,
            final SecretKeySpec encryptionKey, final SecretKeySpec integrityKey) {
        final Map<String, AttributeValue> plaintext = new HashMap<String, AttributeValue>();
        plaintext.put(DEFAULT_HASH_KEY, new AttributeValue().withS(name));
        plaintext.put(DEFAULT_RANGE_KEY, new AttributeValue().withN(Long.toString(version)));
        plaintext.put(MATERIAL_TYPE_VERSION, new AttributeValue().withS("0"));
        plaintext.put(ENCRYPTION_KEY_FIELD,
                new AttributeValue().withB(ByteBuffer.wrap(encryptionKey.getEncoded())));
        plaintext.put(ENCRYPTION_ALGORITHM_FIELD, new AttributeValue().withS(encryptionKey.getAlgorithm()));
        plaintext
        .put(INTEGRITY_KEY_FIELD, new AttributeValue().withB(ByteBuffer.wrap(integrityKey.getEncoded())));
        plaintext.put(INTEGRITY_ALGORITHM_FIELD, new AttributeValue().withS(integrityKey.getAlgorithm()));
        return getEncryptedText(plaintext);
    }

    private EncryptionMaterialsProvider decryptProvider(final Map<String, AttributeValue> item) {
        final Map<String, AttributeValue> plaintext = getPlainText(item);

        final String type = plaintext.get(MATERIAL_TYPE_VERSION).getS();
        final SecretKey encryptionKey;
        final SecretKey integrityKey;
        // This switch statement is to make future extensibility easier and more obvious
        switch (type) {
            case "0": // Only currently supported type
                encryptionKey = new SecretKeySpec(plaintext.get(ENCRYPTION_KEY_FIELD).getB().array(),
                        plaintext.get(ENCRYPTION_ALGORITHM_FIELD).getS());
                integrityKey = new SecretKeySpec(plaintext.get(INTEGRITY_KEY_FIELD).getB().array(), plaintext
                        .get(INTEGRITY_ALGORITHM_FIELD).getS());
                break;
            default:
                throw new IllegalStateException("Unsupported material type: " + type);
        }
        return new WrappedMaterialsProvider(encryptionKey, encryptionKey, integrityKey,
                buildDescription(plaintext));
    }

    private Map<String, AttributeValue> getPlainText(Map<String, AttributeValue> item) {
        try {
            return encryptor.decryptAllFieldsExcept(item,
                    ddbCtx, DEFAULT_HASH_KEY, DEFAULT_RANGE_KEY);
        } catch (final GeneralSecurityException e) {
            throw new AmazonClientException(e);
        }
    }

    private Map<String, AttributeValue> getEncryptedText(Map<String, AttributeValue> plaintext) {
        try {
            return encryptor.encryptAllFieldsExcept(plaintext, ddbCtx, DEFAULT_HASH_KEY,
                    DEFAULT_RANGE_KEY);
        } catch (final GeneralSecurityException e) {
            throw new AmazonClientException(e);
        }
    }

    private Map<String, String> buildDescription(final Map<String, AttributeValue> plaintext) {
        return Collections.singletonMap(META_ID, plaintext.get(DEFAULT_HASH_KEY).getS() + "#"
                + plaintext.get(DEFAULT_RANGE_KEY).getN());
    }

    private static <V> V checkNotNull(final V ref, final String errMsg) {
        if (ref == null) {
            throw new NullPointerException(errMsg);
        } else {
            return ref;
        }
    }
}
