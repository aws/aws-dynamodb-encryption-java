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
package software.amazon.awssdk.enhanced.dynamodb.encryption.providers.store;

import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.enhanced.dynamodb.EncryptionException;
import software.amazon.awssdk.enhanced.dynamodb.encryption.DynamoDBEncryptor;
import software.amazon.awssdk.enhanced.dynamodb.encryption.EncryptionContext;
import software.amazon.awssdk.enhanced.dynamodb.encryption.providers.EncryptionMaterialsProvider;
import software.amazon.awssdk.enhanced.dynamodb.encryption.providers.WrappedMaterialsProvider;
import software.amazon.awssdk.enhanced.dynamodb.internal.Utils;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.*;

/**
 * Provides a simple collection of EncryptionMaterialProviders backed by an encrypted DynamoDB
 * table. This can be used to build key hierarchies or meta providers.
 *
 * <p>Currently, this only supports AES-256 in AESWrap mode and HmacSHA256 for the providers
 * persisted in the table.
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

  /** Default no-op implementation of {@link ExtraDataSupplier}. */
  private static final EmptyExtraDataSupplier EMPTY_EXTRA_DATA_SUPPLIER =
      new EmptyExtraDataSupplier();

  /** DDB fields that must be encrypted. */
  private static final Set<String> ENCRYPTED_FIELDS;

  static {
    final Set<String> tempEncryptedFields = new HashSet<>();
    tempEncryptedFields.add(MATERIAL_TYPE_VERSION);
    tempEncryptedFields.add(ENCRYPTION_KEY_FIELD);
    tempEncryptedFields.add(ENCRYPTION_ALGORITHM_FIELD);
    tempEncryptedFields.add(INTEGRITY_KEY_FIELD);
    tempEncryptedFields.add(INTEGRITY_ALGORITHM_FIELD);
    ENCRYPTED_FIELDS = tempEncryptedFields;
  }

  private final Map<String, ExpectedAttributeValue> doesNotExist;
  private final Set<String> doNotEncrypt;
  private final String tableName;
  private final DynamoDbClient ddb;
  private final DynamoDBEncryptor encryptor;
  private final EncryptionContext ddbCtx;
  private final ExtraDataSupplier extraDataSupplier;

  /** Provides extra data that should be persisted along with the standard material data. */
  public interface ExtraDataSupplier {

    /**
     * Gets the extra data attributes for the specified material name.
     *
     * @param materialName material name.
     * @param version version number.
     * @return plain text of the extra data.
     */
    Map<String, AttributeValue> getAttributes(final String materialName, final long version);

    /**
     * Gets the extra data field names that should be signed only but not encrypted.
     *
     * @return signed only fields.
     */
    Set<String> getSignedOnlyFieldNames();
  }

  /**
   * Create a new MetaStore with specified table name.
   *
   * @param ddb Interface for accessing DynamoDB.
   * @param tableName DynamoDB table name for this {@link MetaStore}.
   * @param encryptor used to perform crypto operations on the record attributes.
   */
  public MetaStore(
      final DynamoDbClient ddb, final String tableName, final DynamoDBEncryptor encryptor) {
    this(ddb, tableName, encryptor, EMPTY_EXTRA_DATA_SUPPLIER);
  }

  /**
   * Create a new MetaStore with specified table name and extra data supplier.
   *
   * @param ddb Interface for accessing DynamoDB.
   * @param tableName DynamoDB table name for this {@link MetaStore}.
   * @param encryptor used to perform crypto operations on the record attributes
   * @param extraDataSupplier provides extra data that should be stored along with the material.
   */
  public MetaStore(
      final DynamoDbClient ddb,
      final String tableName,
      final DynamoDBEncryptor encryptor,
      final ExtraDataSupplier extraDataSupplier) {
    this.ddb = checkNotNull(ddb, "ddb must not be null");
    this.tableName = checkNotNull(tableName, "tableName must not be null");
    this.encryptor = checkNotNull(encryptor, "encryptor must not be null");
    this.extraDataSupplier = checkNotNull(extraDataSupplier, "extraDataSupplier must not be null");

    this.ddbCtx =
        new EncryptionContext.Builder()
            .withTableName(this.tableName)
            .withHashKeyName(DEFAULT_HASH_KEY)
            .withRangeKeyName(DEFAULT_RANGE_KEY)
            .build();

    final Map<String, ExpectedAttributeValue> tmpExpected = new HashMap<>();
    tmpExpected.put(DEFAULT_HASH_KEY, ExpectedAttributeValue.builder().exists(false).build());
    tmpExpected.put(DEFAULT_RANGE_KEY, ExpectedAttributeValue.builder().exists(false).build());
    doesNotExist = Collections.unmodifiableMap(tmpExpected);

    this.doNotEncrypt = getSignedOnlyFields(extraDataSupplier);
  }

  @Override
  public EncryptionMaterialsProvider getProvider(final String materialName, final long version) {
    Map<String, AttributeValue> item = getMaterialItem(materialName, version);
    return decryptProvider(item);
  }

  @Override
  public EncryptionMaterialsProvider getOrCreate(final String materialName, final long nextId) {
    final Map<String, AttributeValue> plaintext = createMaterialItem(materialName, nextId);
    final Map<String, AttributeValue> ciphertext = conditionalPut(getEncryptedText(plaintext));
    return decryptProvider(ciphertext);
  }

  @Override
  public long getMaxVersion(final String materialName) {
    final List<Map<String, AttributeValue>> items =
        ddb.query(
                QueryRequest.builder()
                    .tableName(tableName)
                    .consistentRead(Boolean.TRUE)
                    .keyConditions(
                        Collections.singletonMap(
                            DEFAULT_HASH_KEY,
                           Condition.builder()
                                .comparisonOperator(ComparisonOperator.EQ)
                                .attributeValueList(
                                        AttributeValue.builder().s(materialName).build())
                              .build()))
                    .limit(1)
                    .scanIndexForward(false)
                    .attributesToGet(DEFAULT_RANGE_KEY).build())
                .items();
    if (items.isEmpty()) {
      return -1L;
    } else {
      return Long.parseLong(items.get(0).get(DEFAULT_RANGE_KEY).n());
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
   * This API retrieves the intermediate keys from the source region and replicates it in the target
   * region.
   *
   * @param materialName material name of the encryption material.
   * @param version version of the encryption material.
   * @param targetMetaStore target MetaStore where the encryption material to be stored.
   */
  public void replicate(
      final String materialName, final long version, final MetaStore targetMetaStore) {
    try {
      Map<String, AttributeValue> item = getMaterialItem(materialName, version);
      final Map<String, AttributeValue> plainText = getPlainText(item);
      final Map<String, AttributeValue> encryptedText = targetMetaStore.getEncryptedText(plainText);
      final PutItemRequest put =
          PutItemRequest.builder()
              .tableName(targetMetaStore.tableName)
              .item(encryptedText)
              .expected(doesNotExist)
            .build();
      targetMetaStore.ddb.putItem(put);
    } catch (ConditionalCheckFailedException e) {
      // Item already present.
    }
  }

  private Map<String, AttributeValue> getMaterialItem(
      final String materialName, final long version) {
    final Map<String, AttributeValue> ddbKey = new HashMap<>();
    ddbKey.put(DEFAULT_HASH_KEY, AttributeValue.builder().s(materialName).build());
    ddbKey.put(DEFAULT_RANGE_KEY, AttributeValue.builder().n(Long.toString(version)).build());
    final Map<String, AttributeValue> item = ddbGet(ddbKey);
    if (item == null || item.isEmpty()) {
      throw new IndexOutOfBoundsException("No material found: " + materialName + "#" + version);
    }
    return item;
  }

  /**
   * Creates a DynamoDB Table with the correct properties to be used with a ProviderStore.
   *
   * @param ddb interface for accessing DynamoDB
   * @param tableName name of table that stores the meta data of the material.
   * @param provisionedThroughput required provisioned throughput of the this table.
   * @return result of create table request.
   */
  public static CreateTableResponse createTable(
      final DynamoDbClient ddb,
      final String tableName,
      final ProvisionedThroughput provisionedThroughput) {
    return ddb.createTable(
            CreateTableRequest.builder()
                    .tableName(tableName)
                    .attributeDefinitions(
                            AttributeDefinition.builder()
                                    .attributeName(DEFAULT_HASH_KEY)
                                    .attributeType(ScalarAttributeType.S)
                                    .build(),
                            AttributeDefinition.builder()
                                    .attributeName(DEFAULT_RANGE_KEY)
                                    .attributeType(ScalarAttributeType.N)
                                    .build())
                    .keySchema(
                            KeySchemaElement.builder()
                                    .attributeName(DEFAULT_HASH_KEY)
                                    .keyType(KeyType.HASH)
                                    .build(),
                            KeySchemaElement.builder()
                                    .attributeName(DEFAULT_RANGE_KEY)
                                    .keyType(KeyType.RANGE)
                                    .build())
                    .provisionedThroughput(provisionedThroughput)
                    .build());
  }

  /**
   * Empty extra data supplier. This default class is intended to simplify the default
   * implementation of {@link MetaStore}.
   */
  private static class EmptyExtraDataSupplier implements ExtraDataSupplier {
    @Override
    public Map<String, AttributeValue> getAttributes(String materialName, long version) {
      return Collections.emptyMap();
    }

    @Override
    public Set<String> getSignedOnlyFieldNames() {
      return Collections.emptySet();
    }
  }

  /**
   * Get a set of fields that must be signed but not encrypted.
   *
   * @param extraDataSupplier extra data supplier that is used to return sign only field names.
   * @return fields that must be signed.
   */
  private static Set<String> getSignedOnlyFields(final ExtraDataSupplier extraDataSupplier) {
    final Set<String> signedOnlyFields = extraDataSupplier.getSignedOnlyFieldNames();
    for (final String signedOnlyField : signedOnlyFields) {
      if (ENCRYPTED_FIELDS.contains(signedOnlyField)) {
        throw new IllegalArgumentException(signedOnlyField + " must be encrypted");
      }
    }

    // fields that should not be encrypted
    final Set<String> doNotEncryptFields = new HashSet<>();
    doNotEncryptFields.add(DEFAULT_HASH_KEY);
    doNotEncryptFields.add(DEFAULT_RANGE_KEY);
    doNotEncryptFields.addAll(signedOnlyFields);
    return Collections.unmodifiableSet(doNotEncryptFields);
  }

  private Map<String, AttributeValue> conditionalPut(final Map<String, AttributeValue> item) {
    try {
      final PutItemRequest put =
          PutItemRequest.builder()
                  .tableName(tableName)
                  .item(item)
                  .expected(doesNotExist)
                  .build();
      ddb.putItem(put);
      return item;
    } catch (final ConditionalCheckFailedException ex) {
      final Map<String, AttributeValue> ddbKey = new HashMap<>();
      ddbKey.put(DEFAULT_HASH_KEY, item.get(DEFAULT_HASH_KEY));
      ddbKey.put(DEFAULT_RANGE_KEY, item.get(DEFAULT_RANGE_KEY));
      return ddbGet(ddbKey);
    }
  }

  private Map<String, AttributeValue> ddbGet(final Map<String, AttributeValue> ddbKey) {
    return ddb.getItem(
            GetItemRequest.builder()
                    .tableName(tableName)
                    .consistentRead(true)
                    .key(ddbKey)
                    .build())
            .item();
  }

  /**
   * Build an material item for a given material name and version with newly generated encryption
   * and integrity keys.
   *
   * @param materialName material name.
   * @param version version of the material.
   * @return newly generated plaintext material item.
   */
  private Map<String, AttributeValue> createMaterialItem(
      final String materialName, final long version) {
    final SecretKeySpec encryptionKey = new SecretKeySpec(Utils.getRandom(32), DEFAULT_ENCRYPTION);
    final SecretKeySpec integrityKey = new SecretKeySpec(Utils.getRandom(32), DEFAULT_INTEGRITY);

    final Map<String, AttributeValue> plaintext = new HashMap<String, AttributeValue>();
    plaintext.put(DEFAULT_HASH_KEY, AttributeValue.builder().s(materialName).build());
    plaintext.put(DEFAULT_RANGE_KEY, AttributeValue.builder().n(Long.toString(version)).build());
    plaintext.put(MATERIAL_TYPE_VERSION, AttributeValue.builder().s("0").build());
    plaintext.put(
        ENCRYPTION_KEY_FIELD,
        AttributeValue.builder()
                .b(SdkBytes.fromByteArray(encryptionKey.getEncoded()))
                .build());
    plaintext.put(
        ENCRYPTION_ALGORITHM_FIELD,
        AttributeValue.builder()
                .s(encryptionKey.getAlgorithm())
                .build());
    plaintext.put(
        INTEGRITY_KEY_FIELD,
        AttributeValue.builder()
                .b(SdkBytes.fromByteArray(integrityKey.getEncoded()))
                .build());
    plaintext.put(
        INTEGRITY_ALGORITHM_FIELD,
        AttributeValue.builder()
                .s(integrityKey.getAlgorithm())
                .build());
    plaintext.putAll(extraDataSupplier.getAttributes(materialName, version));

    return plaintext;
  }

  private EncryptionMaterialsProvider decryptProvider(final Map<String, AttributeValue> item) {
    final Map<String, AttributeValue> plaintext = getPlainText(item);

    final String type = plaintext.get(MATERIAL_TYPE_VERSION).s();
    final SecretKey encryptionKey;
    final SecretKey integrityKey;
    // This switch statement is to make future extensibility easier and more obvious
    switch (type) {
      case "0": // Only currently supported type
        encryptionKey =
            new SecretKeySpec(
                plaintext.get(ENCRYPTION_KEY_FIELD).b().asByteArray(),
                plaintext.get(ENCRYPTION_ALGORITHM_FIELD).s());
        integrityKey =
            new SecretKeySpec(
                plaintext.get(INTEGRITY_KEY_FIELD).b().asByteArray(),
                plaintext.get(INTEGRITY_ALGORITHM_FIELD).s());
        break;
      default:
        throw new IllegalStateException("Unsupported material type: " + type);
    }
    return new WrappedMaterialsProvider(
        encryptionKey, encryptionKey, integrityKey, buildDescription(plaintext));
  }

  /**
   * Decrypts attributes in the ciphertext item using {@link DynamoDBEncryptor}. except the
   * attribute names specified in doNotEncrypt.
   *
   * @param ciphertext the ciphertext to be decrypted.
   * @throws EncryptionException when failed to decrypt material item.
   * @return decrypted item.
   */
  private Map<String, AttributeValue> getPlainText(final Map<String, AttributeValue> ciphertext) {
    try {
      return encryptor.decryptAllFieldsExcept(ciphertext, ddbCtx, doNotEncrypt);
    } catch (final GeneralSecurityException e) {
      throw new EncryptionException(e);
    }
  }

  /**
   * Encrypts attributes in the plaintext item using {@link DynamoDBEncryptor}. except the attribute
   * names specified in doNotEncrypt.
   *
   * @throws EncryptionException when failed to encrypt material item.
   * @param plaintext plaintext to be encrypted.
   */
  private Map<String, AttributeValue> getEncryptedText(Map<String, AttributeValue> plaintext) {
    try {
      return encryptor.encryptAllFieldsExcept(plaintext, ddbCtx, doNotEncrypt);
    } catch (final GeneralSecurityException e) {
      throw new EncryptionException(e);
    }
  }

  private Map<String, String> buildDescription(final Map<String, AttributeValue> plaintext) {
    return Collections.singletonMap(
        META_ID,
        plaintext.get(DEFAULT_HASH_KEY).s() + "#" + plaintext.get(DEFAULT_RANGE_KEY).n());
  }

  private static <V> V checkNotNull(final V ref, final String errMsg) {
    if (ref == null) {
      throw new NullPointerException(errMsg);
    } else {
      return ref;
    }
  }
}
