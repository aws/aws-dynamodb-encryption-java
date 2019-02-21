/*
 * Copyright 2014 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 *  http://aws.amazon.com/apache2.0
 *
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */
package com.amazonaws.services.dynamodbv2.datamodeling;

import com.amazonaws.services.dynamodbv2.AmazonDynamoDB;
import com.amazonaws.services.dynamodbv2.datamodeling.DynamoDBMapperConfig.SaveBehavior;
import com.amazonaws.services.dynamodbv2.datamodeling.encryption.DynamoDBEncryptor;
import com.amazonaws.services.dynamodbv2.datamodeling.encryption.providers.AsymmetricStaticProvider;
import com.amazonaws.services.dynamodbv2.datamodeling.encryption.providers.EncryptionMaterialsProvider;
import com.amazonaws.services.dynamodbv2.datamodeling.encryption.providers.MostRecentProvider;
import com.amazonaws.services.dynamodbv2.datamodeling.encryption.providers.SymmetricStaticProvider;
import com.amazonaws.services.dynamodbv2.datamodeling.encryption.providers.WrappedMaterialsProvider;
import com.amazonaws.services.dynamodbv2.datamodeling.encryption.providers.store.MetaStore;
import com.amazonaws.services.dynamodbv2.datamodeling.internal.AttributeValueMarshaller;
import com.amazonaws.services.dynamodbv2.local.embedded.DynamoDBEmbedded;
import com.amazonaws.services.dynamodbv2.model.AttributeAction;
import com.amazonaws.services.dynamodbv2.model.AttributeDefinition;
import com.amazonaws.services.dynamodbv2.model.AttributeValue;
import com.amazonaws.services.dynamodbv2.model.AttributeValueUpdate;
import com.amazonaws.services.dynamodbv2.model.ConditionalCheckFailedException;
import com.amazonaws.services.dynamodbv2.model.CreateTableRequest;
import com.amazonaws.services.dynamodbv2.model.KeySchemaElement;
import com.amazonaws.services.dynamodbv2.model.KeyType;
import com.amazonaws.services.dynamodbv2.model.ProvisionedThroughput;
import com.amazonaws.services.dynamodbv2.model.PutItemRequest;
import com.amazonaws.services.dynamodbv2.model.ScalarAttributeType;
import com.amazonaws.services.dynamodbv2.model.ScanRequest;
import com.amazonaws.services.dynamodbv2.model.ScanResult;
import com.amazonaws.services.dynamodbv2.model.UpdateItemRequest;
import com.amazonaws.services.dynamodbv2.testing.types.BaseClass;
import com.amazonaws.services.dynamodbv2.testing.types.HashKeyOnly;
import com.amazonaws.services.dynamodbv2.testing.types.KeysOnly;
import com.amazonaws.services.dynamodbv2.testing.types.Mixed;
import com.amazonaws.services.dynamodbv2.testing.types.SignOnly;
import com.amazonaws.services.dynamodbv2.testing.types.Untouched;
import com.amazonaws.util.Base64;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;

import static org.testng.AssertJUnit.assertEquals;
import static org.testng.AssertJUnit.assertFalse;
import static org.testng.AssertJUnit.assertNull;
import static org.testng.AssertJUnit.assertTrue;
import static org.testng.AssertJUnit.fail;

public class TransformerHolisticTests {
    private static final SecretKey aesKey = new SecretKeySpec(new byte[]{0,
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}, "AES");
    private static final SecretKey hmacKey = new SecretKeySpec(new byte[]{0,
            1, 2, 3, 4, 5, 6, 7}, "HmacSHA256");
    private static final String rsaEncPub = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtiNSLSvT9cExXOcD0dGZ"
            + "9DFEMHw8895gAZcCdSppDrxbD7XgZiQYTlgt058i5fS+l11guAUJtKt5sZ2u8Fx0"
            + "K9pxMdlczGtvQJdx/LQETEnLnfzAijvHisJ8h6dQOVczM7t01KIkS24QZElyO+kY"
            + "qMWLytUV4RSHnrnIuUtPHCe6LieDWT2+1UBguxgtFt1xdXlquACLVv/Em3wp40Xc"
            + "bIwzhqLitb98rTY/wqSiGTz1uvvBX46n+f2j3geZKCEDGkWcXYw3dH4lRtDWTbqw"
            + "eRcaNDT/MJswQlBk/Up9KCyN7gjX67gttiCO6jMoTNDejGeJhG4Dd2o0vmn8WJlr"
            + "5wIDAQAB";
    private static final String rsaEncPriv = "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC2I1ItK9P1wTFc"
            + "5wPR0Zn0MUQwfDzz3mABlwJ1KmkOvFsPteBmJBhOWC3TnyLl9L6XXWC4BQm0q3mx"
            + "na7wXHQr2nEx2VzMa29Al3H8tARMScud/MCKO8eKwnyHp1A5VzMzu3TUoiRLbhBk"
            + "SXI76RioxYvK1RXhFIeeuci5S08cJ7ouJ4NZPb7VQGC7GC0W3XF1eWq4AItW/8Sb"
            + "fCnjRdxsjDOGouK1v3ytNj/CpKIZPPW6+8Ffjqf5/aPeB5koIQMaRZxdjDd0fiVG"
            + "0NZNurB5Fxo0NP8wmzBCUGT9Sn0oLI3uCNfruC22II7qMyhM0N6MZ4mEbgN3ajS+"
            + "afxYmWvnAgMBAAECggEBAIIU293zDWDZZ73oJ+w0fHXQsdjHAmlRitPX3CN99KZX"
            + "k9m2ldudL9bUV3Zqk2wUzgIg6LDEuFfWmAVojsaP4VBopKtriEFfAYfqIbjPgLpT"
            + "gh8FoyWW6D6MBJCFyGALjUAHQ7uRScathvt5ESMEqV3wKJTmdsfX97w/B8J+rLN3"
            + "3fT3ZJUck5duZ8XKD+UtX1Y3UE1hTWo3Ae2MFND964XyUqy+HaYXjH0x6dhZzqyJ"
            + "/OJ/MPGeMJgxp+nUbMWerwxrLQceNFVgnQgHj8e8k4fd04rkowkkPua912gNtmz7"
            + "DuIEvcMnY64z585cn+cnXUPJwtu3JbAmn/AyLsV9FLECgYEA798Ut/r+vORB16JD"
            + "KFu38pQCgIbdCPkXeI0DC6u1cW8JFhgRqi+AqSrEy5SzY3IY7NVMSRsBI9Y026Bl"
            + "R9OQwTrOzLRAw26NPSDvbTkeYXlY9+hX7IovHjGkho/OxyTJ7bKRDYLoNCz56BC1"
            + "khIWvECpcf/fZU0nqOFVFqF3H/UCgYEAwmJ4rjl5fksTNtNRL6ivkqkHIPKXzk5w"
            + "C+L90HKNicic9bqyX8K4JRkGKSNYN3mkjrguAzUlEld390qNBw5Lu7PwATv0e2i+"
            + "6hdwJsjTKNpj7Nh4Mieq6d7lWe1L8FLyHEhxgIeQ4BgqrVtPPOH8IBGpuzVZdWwI"
            + "dgOvEvAi/usCgYBdfk3NB/+SEEW5jn0uldE0s4vmHKq6fJwxWIT/X4XxGJ4qBmec"
            + "NbeoOAtMbkEdWbNtXBXHyMbA+RTRJctUG5ooNou0Le2wPr6+PMAVilXVGD8dIWpj"
            + "v9htpFvENvkZlbU++IKhCY0ICR++3ARpUrOZ3Hou/NRN36y9nlZT48tSoQKBgES2"
            + "Bi6fxmBsLUiN/f64xAc1lH2DA0I728N343xRYdK4hTMfYXoUHH+QjurvwXkqmI6S"
            + "cEFWAdqv7IoPYjaCSSb6ffYRuWP+LK4WxuAO0QV53SSViDdCalntHmlhRhyXVVnG"
            + "CckDIqT0JfHNev7savDzDWpNe2fUXlFJEBPDqrstAoGBAOpd5+QBHF/tP5oPILH4"
            + "aD/zmqMH7VtB+b/fOPwtIM+B/WnU7hHLO5t2lJYu18Be3amPkfoQIB7bpkM3Cer2"
            + "G7Jw+TcHrY+EtIziDB5vwau1fl4VcbA9SfWpBojJ5Ifo9ELVxGiK95WxeQNSmLUy"
            + "7AJzhK1Gwey8a/v+xfqiu9sE";
    private static final PrivateKey rsaPriv;
    private static final PublicKey rsaPub;
    private static final KeyPair rsaPair;
    private static final EncryptionMaterialsProvider symProv;
    private static final EncryptionMaterialsProvider asymProv;
    private static final EncryptionMaterialsProvider symWrappedProv;

    private AmazonDynamoDB client;
    // AttributeEncryptor *must* be used with SaveBehavior.CLOBBER to avoid the risk of data corruption.
    private static final DynamoDBMapperConfig CLOBBER_CONFIG =
            DynamoDBMapperConfig.builder().withSaveBehavior(SaveBehavior.CLOBBER).build();
    private static final BaseClass ENCRYPTED_TEST_VALUE = new BaseClass();
    private static final Mixed MIXED_TEST_VALUE = new Mixed();
    private static final SignOnly SIGNED_TEST_VALUE = new SignOnly();
    private static final Untouched UNTOUCHED_TEST_VALUE = new Untouched();

    private static final BaseClass ENCRYPTED_TEST_VALUE_2 = new BaseClass();
    private static final Mixed MIXED_TEST_VALUE_2 = new Mixed();
    private static final SignOnly SIGNED_TEST_VALUE_2 = new SignOnly();
    private static final Untouched UNTOUCHED_TEST_VALUE_2 = new Untouched();

    private EncryptionMaterialsProvider mrProv;

    static {
        try {
            KeyFactory rsaFact = KeyFactory.getInstance("RSA");
            rsaPub = rsaFact.generatePublic(new X509EncodedKeySpec(Base64
                    .decode(rsaEncPub)));
            rsaPriv = rsaFact.generatePrivate(new PKCS8EncodedKeySpec(Base64
                    .decode(rsaEncPriv)));
            rsaPair = new KeyPair(rsaPub, rsaPriv);
        } catch (GeneralSecurityException ex) {
            throw new RuntimeException(ex);
        }
        symProv = new SymmetricStaticProvider(aesKey, hmacKey);
        asymProv = new AsymmetricStaticProvider(rsaPair, rsaPair);
        symWrappedProv = new WrappedMaterialsProvider(aesKey, aesKey, hmacKey);

        ENCRYPTED_TEST_VALUE.setHashKey(5);
        ENCRYPTED_TEST_VALUE.setRangeKey(7);
        ENCRYPTED_TEST_VALUE.setVersion(0);
        ENCRYPTED_TEST_VALUE.setIntValue(123);
        ENCRYPTED_TEST_VALUE.setStringValue("Hello world!");
        ENCRYPTED_TEST_VALUE.setByteArrayValue(new byte[]{0, 1, 2, 3, 4, 5});
        ENCRYPTED_TEST_VALUE.setStringSet(new HashSet<String>(Arrays.asList(
                "Goodbye", "Cruel", "World", "?")));
        ENCRYPTED_TEST_VALUE.setIntSet(new HashSet<Integer>(Arrays.asList(1,
                200, 10, 15, 0)));

        MIXED_TEST_VALUE.setHashKey(6);
        MIXED_TEST_VALUE.setRangeKey(8);
        MIXED_TEST_VALUE.setVersion(0);
        MIXED_TEST_VALUE.setIntValue(123);
        MIXED_TEST_VALUE.setStringValue("Hello world!");
        MIXED_TEST_VALUE.setByteArrayValue(new byte[]{0, 1, 2, 3, 4, 5});
        MIXED_TEST_VALUE.setStringSet(new HashSet<String>(Arrays.asList(
                "Goodbye", "Cruel", "World", "?")));
        MIXED_TEST_VALUE.setIntSet(new HashSet<Integer>(Arrays.asList(1, 200,
                10, 15, 0)));

        SIGNED_TEST_VALUE.setHashKey(8);
        SIGNED_TEST_VALUE.setRangeKey(10);
        SIGNED_TEST_VALUE.setVersion(0);
        SIGNED_TEST_VALUE.setIntValue(123);
        SIGNED_TEST_VALUE.setStringValue("Hello world!");
        SIGNED_TEST_VALUE.setByteArrayValue(new byte[]{0, 1, 2, 3, 4, 5});
        SIGNED_TEST_VALUE.setStringSet(new HashSet<String>(Arrays.asList(
                "Goodbye", "Cruel", "World", "?")));
        SIGNED_TEST_VALUE.setIntSet(new HashSet<Integer>(Arrays.asList(1, 200,
                10, 15, 0)));

        UNTOUCHED_TEST_VALUE.setHashKey(7);
        UNTOUCHED_TEST_VALUE.setRangeKey(9);
        UNTOUCHED_TEST_VALUE.setVersion(0);
        UNTOUCHED_TEST_VALUE.setIntValue(123);
        UNTOUCHED_TEST_VALUE.setStringValue("Hello world!");
        UNTOUCHED_TEST_VALUE.setByteArrayValue(new byte[]{0, 1, 2, 3, 4, 5});
        UNTOUCHED_TEST_VALUE.setStringSet(new HashSet<String>(Arrays.asList(
                "Goodbye", "Cruel", "World", "?")));
        UNTOUCHED_TEST_VALUE.setIntSet(new HashSet<Integer>(Arrays.asList(1,
                200, 10, 15, 0)));

        // Now storing doubles
        ENCRYPTED_TEST_VALUE_2.setHashKey(5);
        ENCRYPTED_TEST_VALUE_2.setRangeKey(7);
        ENCRYPTED_TEST_VALUE_2.setVersion(0);
        ENCRYPTED_TEST_VALUE_2.setIntValue(123);
        ENCRYPTED_TEST_VALUE_2.setStringValue("Hello world!");
        ENCRYPTED_TEST_VALUE_2.setByteArrayValue(new byte[]{0, 1, 2, 3, 4, 5});
        ENCRYPTED_TEST_VALUE_2.setStringSet(new HashSet<String>(Arrays.asList(
                "Goodbye", "Cruel", "World", "?")));
        ENCRYPTED_TEST_VALUE_2.setIntSet(new HashSet<Integer>(Arrays.asList(1,
                200, 10, 15, 0)));
        ENCRYPTED_TEST_VALUE_2.setDoubleValue(15);
        ENCRYPTED_TEST_VALUE_2.setDoubleSet(
                new HashSet<Double>(Arrays.asList(15.0D, 7.6D, -3D, -34.2D, 0.0D)));

        MIXED_TEST_VALUE_2.setHashKey(6);
        MIXED_TEST_VALUE_2.setRangeKey(8);
        MIXED_TEST_VALUE_2.setVersion(0);
        MIXED_TEST_VALUE_2.setIntValue(123);
        MIXED_TEST_VALUE_2.setStringValue("Hello world!");
        MIXED_TEST_VALUE_2.setByteArrayValue(new byte[]{0, 1, 2, 3, 4, 5});
        MIXED_TEST_VALUE_2.setStringSet(new HashSet<String>(Arrays.asList(
                "Goodbye", "Cruel", "World", "?")));
        MIXED_TEST_VALUE_2.setIntSet(new HashSet<Integer>(Arrays.asList(1, 200,
                10, 15, 0)));
        MIXED_TEST_VALUE_2.setDoubleValue(15);
        MIXED_TEST_VALUE_2.setDoubleSet(
                new HashSet<Double>(Arrays.asList(15.0D, 7.6D, -3D, -34.2D, 0.0D)));

        SIGNED_TEST_VALUE_2.setHashKey(8);
        SIGNED_TEST_VALUE_2.setRangeKey(10);
        SIGNED_TEST_VALUE_2.setVersion(0);
        SIGNED_TEST_VALUE_2.setIntValue(123);
        SIGNED_TEST_VALUE_2.setStringValue("Hello world!");
        SIGNED_TEST_VALUE_2.setByteArrayValue(new byte[]{0, 1, 2, 3, 4, 5});
        SIGNED_TEST_VALUE_2.setStringSet(new HashSet<String>(Arrays.asList(
                "Goodbye", "Cruel", "World", "?")));
        SIGNED_TEST_VALUE_2.setIntSet(new HashSet<Integer>(Arrays.asList(1, 200,
                10, 15, 0)));
        SIGNED_TEST_VALUE_2.setDoubleValue(15);
        SIGNED_TEST_VALUE_2.setDoubleSet(
                new HashSet<Double>(Arrays.asList(15.0D, 7.6D, -3D, -34.2D, 0.0D)));

        UNTOUCHED_TEST_VALUE_2.setHashKey(7);
        UNTOUCHED_TEST_VALUE_2.setRangeKey(9);
        UNTOUCHED_TEST_VALUE_2.setVersion(0);
        UNTOUCHED_TEST_VALUE_2.setIntValue(123);
        UNTOUCHED_TEST_VALUE_2.setStringValue("Hello world!");
        UNTOUCHED_TEST_VALUE_2.setByteArrayValue(new byte[]{0, 1, 2, 3, 4, 5});
        UNTOUCHED_TEST_VALUE_2.setStringSet(new HashSet<String>(Arrays.asList(
                "Goodbye", "Cruel", "World", "?")));
        UNTOUCHED_TEST_VALUE_2.setIntSet(new HashSet<Integer>(Arrays.asList(1,
                200, 10, 15, 0)));
        UNTOUCHED_TEST_VALUE_2.setDoubleValue(15);
        UNTOUCHED_TEST_VALUE_2.setDoubleSet(
                new HashSet<Double>(Arrays.asList(15.0D, 7.6D, -3D, -34.2D, 0.0D)));

    }

    @BeforeMethod
    public void setUp() {
        client = DynamoDBEmbedded.create();

        ArrayList<AttributeDefinition> attrDef = new ArrayList<AttributeDefinition>();
        attrDef.add(new AttributeDefinition().withAttributeName("hashKey").withAttributeType(ScalarAttributeType.N));
        attrDef.add(new AttributeDefinition().withAttributeName("rangeKey").withAttributeType(ScalarAttributeType.N));

        ArrayList<KeySchemaElement> keySchema = new ArrayList<KeySchemaElement>();
        keySchema.add(new KeySchemaElement().withAttributeName("hashKey").withKeyType(KeyType.HASH));
        keySchema.add(new KeySchemaElement().withAttributeName("rangeKey").withKeyType(KeyType.RANGE));

        client.createTable(new CreateTableRequest().withTableName("TableName")
                .withAttributeDefinitions(attrDef)
                .withKeySchema(keySchema)
                .withProvisionedThroughput(new ProvisionedThroughput(100L, 100L)));

        attrDef = new ArrayList<AttributeDefinition>();
        attrDef.add(new AttributeDefinition().withAttributeName("hashKey").withAttributeType(ScalarAttributeType.S));
        keySchema = new ArrayList<KeySchemaElement>();
        keySchema.add(new KeySchemaElement().withAttributeName("hashKey").withKeyType(KeyType.HASH));

        client.createTable(new CreateTableRequest().withTableName("HashKeyOnly")
                .withAttributeDefinitions(attrDef)
                .withKeySchema(keySchema)
                .withProvisionedThroughput(new ProvisionedThroughput(100L, 100L)));

        attrDef = new ArrayList<AttributeDefinition>();
        attrDef.add(new AttributeDefinition().withAttributeName("hashKey").withAttributeType(ScalarAttributeType.B));
        attrDef.add(new AttributeDefinition().withAttributeName("rangeKey").withAttributeType(ScalarAttributeType.N));

        keySchema = new ArrayList<KeySchemaElement>();
        keySchema.add(new KeySchemaElement().withAttributeName("hashKey").withKeyType(KeyType.HASH));
        keySchema.add(new KeySchemaElement().withAttributeName("rangeKey").withKeyType(KeyType.RANGE));

        client.createTable(new CreateTableRequest().withTableName("DeterministicTable")
                .withAttributeDefinitions(attrDef)
                .withKeySchema(keySchema)
                .withProvisionedThroughput(new ProvisionedThroughput(100L, 100L)));

        MetaStore.createTable(client, "metastore", new ProvisionedThroughput(100L, 100L));
        mrProv = new MostRecentProvider(new MetaStore(client, "metastore", DynamoDBEncryptor.getInstance(symProv)), "materialName", 1000);

    }

    @Test
    public void simpleSaveLoad() {
        DynamoDBMapper mapper = new DynamoDBMapper(client, CLOBBER_CONFIG, new AttributeEncryptor(symProv));
        Mixed obj = new Mixed();
        obj.setHashKey(0);
        obj.setRangeKey(15);
        obj.setIntSet(new HashSet<Integer>());
        obj.getIntSet().add(3);
        obj.getIntSet().add(5);
        obj.getIntSet().add(7);
        obj.setDoubleValue(15);
        obj.setStringValue("Blargh!");
        obj.setDoubleSet(
                new HashSet<Double>(Arrays.asList(15.0D, 7.6D, -3D, -34.2D, 0.0D)));

        mapper.save(obj);

        Mixed result = mapper.load(Mixed.class, 0, 15);
        assertEquals(obj, result);

        result.setStringValue("Foo");
        mapper.save(result);

        Mixed result2 = mapper.load(Mixed.class, 0, 15);
        assertEquals(result, result2);

        mapper.delete(result);
        assertNull(mapper.load(Mixed.class, 0, 15));
    }

    /**
     * This test ensures that optimistic locking can be successfully done through the {@link DynamoDBMapper} when
     * combined with the @{link AttributeEncryptor}. Specifically it checks that {@link SaveBehavior#PUT} properly
     * enforces versioning and will result in a {@link ConditionalCheckFailedException} when optimistic locking should
     * prevent a write. Finally, it checks that {@link SaveBehavior#CLOBBER} properly ignores optimistic locking and
     * overwrites the old value.
     */
    @Test
    public void optimisticLockingTest() {
        DynamoDBMapper mapper = new DynamoDBMapper(client,
                DynamoDBMapperConfig.builder()
                        .withSaveBehavior(SaveBehavior.PUT).build(),
                new AttributeEncryptor(symProv));
        DynamoDBMapper clobberMapper = new DynamoDBMapper(client, CLOBBER_CONFIG, new AttributeEncryptor(symProv));

        /*
         * Lineage of objects
         * expected -> v1 -> v2 -> v3
         *                |
         *                -> v2_2 -> clobbered
         * Splitting the lineage after v1 is what should
         * cause the ConditionalCheckFailedException.
         */
        final int hashKey = 0;
        final int rangeKey = 15;
        final Mixed expected = new Mixed();
        expected.setHashKey(hashKey);
        expected.setRangeKey(rangeKey);
        expected.setIntSet(new HashSet<Integer>());
        expected.getIntSet().add(3);
        expected.getIntSet().add(5);
        expected.getIntSet().add(7);
        expected.setDoubleValue(15);
        expected.setStringValue("Blargh!");
        expected.setDoubleSet(
                new HashSet<Double>(Arrays.asList(15.0D, 7.6D, -3D, -34.2D, 0.0D)));

        mapper.save(expected);
        Mixed v1 = mapper.load(Mixed.class, hashKey, rangeKey);
        assertEquals(expected, v1);
        v1.setStringValue("New value");
        mapper.save(v1);
        Mixed v2 = mapper.load(Mixed.class, hashKey, rangeKey);
        assertEquals(v1, v2);
        Mixed v2_2 = mapper.load(Mixed.class, hashKey, rangeKey);

        v2.getIntSet().add(-37);
        mapper.save(v2);
        Mixed v3 = mapper.load(Mixed.class, hashKey, rangeKey);
        assertEquals(v2, v3);
        assertTrue(v3.getIntSet().contains(-37));

        // This should fail due to optimistic locking
        v2_2.getIntSet().add(38);
        try {
            mapper.save(v2_2);
            fail("Expected ConditionalCheckFailedException");
        } catch (ConditionalCheckFailedException ex) {
            // Expected exception
        }

        // Force the update with clobber
        clobberMapper.save(v2_2);
        Mixed clobbered = mapper.load(Mixed.class, hashKey, rangeKey);
        assertEquals(v2_2, clobbered);
        assertTrue(clobbered.getIntSet().contains(38));
        assertFalse(clobbered.getIntSet().contains(-37));
    }

    @Test
    public void leadingAndTrailingZeros() {
        DynamoDBMapper mapper = new DynamoDBMapper(client, CLOBBER_CONFIG, new AttributeEncryptor(symProv));
        Mixed obj = new Mixed();
        obj.setHashKey(0);
        obj.setRangeKey(15);
        obj.setIntSet(new HashSet<Integer>());
        obj.getIntSet().add(3);
        obj.getIntSet().add(5);
        obj.getIntSet().add(7);
        obj.setStringValue("Blargh!");
        obj.setDoubleValue(15);
        obj.setDoubleSet(
                new HashSet<Double>(Arrays.asList(15.0D, 7.6D, -3D, -34.2D, 0.0D)));

        mapper.save(obj);


        // TODO: Update the mock to handle this appropriately.
        // DynamoDb discards leading and trailing zeros from numbers
        Map<String, AttributeValue> key = new HashMap<String, AttributeValue>();
        key.put("hashKey", new AttributeValue().withN("0"));
        key.put("rangeKey", new AttributeValue().withN("15"));
        Map<String, AttributeValueUpdate> attributeUpdates = new HashMap<String, AttributeValueUpdate>();
        attributeUpdates.put("doubleValue", new AttributeValueUpdate(new AttributeValue().withN("15"), AttributeAction.PUT));
        UpdateItemRequest update = new UpdateItemRequest("TableName", key, attributeUpdates);
        client.updateItem(update);


        Mixed result = mapper.load(Mixed.class, 0, 15);
        assertEquals(obj, result);

        result.setStringValue("Foo");
        mapper.save(result);

        Mixed result2 = mapper.load(Mixed.class, 0, 15);
        assertEquals(result, result2);

        mapper.delete(result);
        assertNull(mapper.load(Mixed.class, 0, 15));
    }

    @Test
    public void simpleSaveLoadAsym() {
        DynamoDBMapper mapper = new DynamoDBMapper(client, CLOBBER_CONFIG, new AttributeEncryptor(asymProv));

        BaseClass obj = new BaseClass();
        obj.setHashKey(0);
        obj.setRangeKey(15);
        obj.setIntSet(new HashSet<Integer>());
        obj.getIntSet().add(3);
        obj.getIntSet().add(5);
        obj.getIntSet().add(7);
        obj.setDoubleValue(15);
        obj.setStringValue("Blargh!");
        obj.setDoubleSet(
                new HashSet<Double>(Arrays.asList(15.0D, 7.6D, -3D, -34.2D, 0.0D)));
        mapper.save(obj);

        BaseClass result = mapper.load(BaseClass.class, 0, 15);
        assertEquals(obj, result);

        result.setStringValue("Foo");
        mapper.save(result);

        BaseClass result2 = mapper.load(BaseClass.class, 0, 15);
        assertEquals(result, result2);

        mapper.delete(result);
        assertNull(mapper.load(BaseClass.class, 0, 15));
    }

    @Test
    public void simpleSaveLoadHashOnly() {
        DynamoDBMapper mapper = new DynamoDBMapper(client, CLOBBER_CONFIG, new AttributeEncryptor(
                symProv));

        HashKeyOnly obj = new HashKeyOnly("");
        obj.setHashKey("Foo");

        mapper.save(obj);

        HashKeyOnly result = mapper.load(HashKeyOnly.class, "Foo");
        assertEquals(obj, result);

        mapper.delete(obj);
        assertNull(mapper.load(BaseClass.class, 0, 15));
    }

    @Test
    public void simpleSaveLoadKeysOnly() {
        DynamoDBMapper mapper = new DynamoDBMapper(client, CLOBBER_CONFIG, new AttributeEncryptor(
                asymProv));

        KeysOnly obj = new KeysOnly();
        obj.setHashKey(0);
        obj.setRangeKey(15);

        mapper.save(obj);

        KeysOnly result = mapper.load(KeysOnly.class, 0, 15);
        assertEquals(obj, result);

        mapper.delete(obj);
        assertNull(mapper.load(BaseClass.class, 0, 15));
    }

    //    @Test
    public void generateStandardAsymData() {
        generateStandardData(asymProv);
    }

    //    @Test
    public void generateStandardSymData() {
        generateStandardData(symProv);
    }

    //    @Test
    public void generateStandardSymWrappedData() {
        generateStandardData(symWrappedProv);
    }

    //    @Test
    public void generateStandardMetastoreData() {
        generateStandardData(mrProv);
    }

    public void generateStandardData(EncryptionMaterialsProvider prov) {
        DynamoDBMapper mapper = new DynamoDBMapper(client,
                new DynamoDBMapperConfig(SaveBehavior.CLOBBER), new AttributeEncryptor(prov));
        mapper.save(new HashKeyOnly("Foo"));
        mapper.save(new HashKeyOnly("Bar"));
        mapper.save(new HashKeyOnly("Baz"));

        mapper.save(new KeysOnly(0, 1));
        mapper.save(new KeysOnly(0, 2));
        mapper.save(new KeysOnly(0, 3));
        mapper.save(new KeysOnly(1, 1));
        mapper.save(new KeysOnly(1, 2));
        mapper.save(new KeysOnly(1, 3));
        mapper.save(new KeysOnly(5, 1));
        mapper.save(new KeysOnly(6, 2));
        mapper.save(new KeysOnly(7, 3));

        mapper.save(ENCRYPTED_TEST_VALUE_2);
        mapper.save(MIXED_TEST_VALUE_2);
        mapper.save(SIGNED_TEST_VALUE_2);
        mapper.save(UNTOUCHED_TEST_VALUE_2);

        dumpTables();
    }

    // First released version of code. Likely no actual data stored this way
    @Test
    public void testV0SymCompatibility() {
        DynamoDBMapper mapper = new DynamoDBMapper(client,
                new DynamoDBMapperConfig(SaveBehavior.CLOBBER), new AttributeEncryptor(symProv));
        insertV0SymData(client);
        assertVersionCompatibility(mapper);
    }

    @Test
    public void testV0AsymCompatibility() {
        DynamoDBMapper mapper = new DynamoDBMapper(client,
                new DynamoDBMapperConfig(SaveBehavior.CLOBBER), new AttributeEncryptor(asymProv));
        insertV0AsymData(client);
        assertVersionCompatibility(mapper);
    }

    // Identical to V0 except WrappedRawMaterials now stores the cipher
    // transformation used to wrap the keys in "amzn-ddb-wrap-alg" for
    // better compatibility with limited function devices (such as smart-
    // cards) and better guarantees that data will be decrypted properly.
    @Test
    public void testV0FixedWrappingTransformSymCompatibility() {
        DynamoDBMapper mapper = new DynamoDBMapper(client,
                new DynamoDBMapperConfig(SaveBehavior.CLOBBER), new AttributeEncryptor(symProv));
        insertV0FixedWrappingTransformSymData(client);
        assertVersionCompatibility(mapper);
    }

    @Test
    public void testV0FixedWrappingTransformAsymCompatibility() {
        DynamoDBMapper mapper = new DynamoDBMapper(client,
                new DynamoDBMapperConfig(SaveBehavior.CLOBBER), new AttributeEncryptor(asymProv));
        insertV0FixedWrappingTransformAsymData(client);
        assertVersionCompatibility(mapper);
    }

    @Test
    public void testV0FixedWrappingTransformSymWrappedCompatibility() {
        DynamoDBMapper mapper = new DynamoDBMapper(client,
                new DynamoDBMapperConfig(SaveBehavior.CLOBBER), new AttributeEncryptor(symWrappedProv));
        insertV0FixedWrappingTransformSymWrappedData(client);
        assertVersionCompatibility_2(mapper);
    }

    @Test
    public void testV0FixedDoubleSymCompatibility() {
        DynamoDBMapper mapper = new DynamoDBMapper(client,
                new DynamoDBMapperConfig(SaveBehavior.CLOBBER), new AttributeEncryptor(symProv));
        insertV0FixedDoubleSymData(client);
        assertVersionCompatibility_2(mapper);
    }

    @Test
    public void testV0FixedDoubleAsymCompatibility() {
        DynamoDBMapper mapper = new DynamoDBMapper(client,
                new DynamoDBMapperConfig(SaveBehavior.CLOBBER), new AttributeEncryptor(asymProv));
        insertV0FixedDoubleAsymData(client);
        assertVersionCompatibility_2(mapper);
    }

    @Test
    public void testV0MetastoreCompatibility() {
        DynamoDBMapper mapper = new DynamoDBMapper(client,
                new DynamoDBMapperConfig(SaveBehavior.CLOBBER), new AttributeEncryptor(mrProv));
        insertV0MetastoreData(client);
        assertVersionCompatibility_2(mapper);
    }

    private void assertVersionCompatibility(DynamoDBMapper mapper) {
        assertEquals(UNTOUCHED_TEST_VALUE, mapper.load(
                UNTOUCHED_TEST_VALUE.getClass(),
                UNTOUCHED_TEST_VALUE.getHashKey(),
                UNTOUCHED_TEST_VALUE.getRangeKey()));
        assertEquals(
                SIGNED_TEST_VALUE,
                mapper.load(SIGNED_TEST_VALUE.getClass(),
                        SIGNED_TEST_VALUE.getHashKey(),
                        SIGNED_TEST_VALUE.getRangeKey()));
        assertEquals(
                MIXED_TEST_VALUE,
                mapper.load(MIXED_TEST_VALUE.getClass(),
                        MIXED_TEST_VALUE.getHashKey(),
                        MIXED_TEST_VALUE.getRangeKey()));
        assertEquals(ENCRYPTED_TEST_VALUE, mapper.load(
                ENCRYPTED_TEST_VALUE.getClass(),
                ENCRYPTED_TEST_VALUE.getHashKey(),
                ENCRYPTED_TEST_VALUE.getRangeKey()));

        assertEquals("Foo", mapper.load(HashKeyOnly.class, "Foo").getHashKey());
        assertEquals("Bar", mapper.load(HashKeyOnly.class, "Bar").getHashKey());
        assertEquals("Baz", mapper.load(HashKeyOnly.class, "Baz").getHashKey());

        for (int x = 1; x <= 3; ++x) {
            KeysOnly obj = mapper.load(KeysOnly.class, 0, x);
            assertEquals(0, obj.getHashKey());
            assertEquals(x, obj.getRangeKey());

            obj = mapper.load(KeysOnly.class, 1, x);
            assertEquals(1, obj.getHashKey());
            assertEquals(x, obj.getRangeKey());

            obj = mapper.load(KeysOnly.class, 4 + x, x);
            assertEquals(4 + x, obj.getHashKey());
            assertEquals(x, obj.getRangeKey());
        }
    }

    private void assertVersionCompatibility_2(DynamoDBMapper mapper) {
        assertEquals(UNTOUCHED_TEST_VALUE_2, mapper.load(
                UNTOUCHED_TEST_VALUE_2.getClass(),
                UNTOUCHED_TEST_VALUE_2.getHashKey(),
                UNTOUCHED_TEST_VALUE_2.getRangeKey()));
        assertEquals(
                SIGNED_TEST_VALUE_2,
                mapper.load(SIGNED_TEST_VALUE_2.getClass(),
                        SIGNED_TEST_VALUE_2.getHashKey(),
                        SIGNED_TEST_VALUE_2.getRangeKey()));
        assertEquals(
                MIXED_TEST_VALUE_2,
                mapper.load(MIXED_TEST_VALUE_2.getClass(),
                        MIXED_TEST_VALUE_2.getHashKey(),
                        MIXED_TEST_VALUE_2.getRangeKey()));
        assertEquals(ENCRYPTED_TEST_VALUE_2, mapper.load(
                ENCRYPTED_TEST_VALUE_2.getClass(),
                ENCRYPTED_TEST_VALUE_2.getHashKey(),
                ENCRYPTED_TEST_VALUE_2.getRangeKey()));

        assertEquals("Foo", mapper.load(HashKeyOnly.class, "Foo").getHashKey());
        assertEquals("Bar", mapper.load(HashKeyOnly.class, "Bar").getHashKey());
        assertEquals("Baz", mapper.load(HashKeyOnly.class, "Baz").getHashKey());

        for (int x = 1; x <= 3; ++x) {
            KeysOnly obj = mapper.load(KeysOnly.class, 0, x);
            assertEquals(0, obj.getHashKey());
            assertEquals(x, obj.getRangeKey());

            obj = mapper.load(KeysOnly.class, 1, x);
            assertEquals(1, obj.getHashKey());
            assertEquals(x, obj.getRangeKey());

            obj = mapper.load(KeysOnly.class, 4 + x, x);
            assertEquals(4 + x, obj.getHashKey());
            assertEquals(x, obj.getRangeKey());
        }
    }

    private void dumpTables() {
        for (String table : client.listTables().getTableNames()) {
            ScanResult scanResult;
            Map<String, AttributeValue> lastKey = null;
            do {
                scanResult = client.scan(new ScanRequest().withTableName(table).withExclusiveStartKey(lastKey));
                lastKey = scanResult.getLastEvaluatedKey();
                for (Map<String, AttributeValue> map : scanResult.getItems()) {
                    for (Map.Entry<String, AttributeValue> item : map.entrySet()) {
                        System.out.print("item.put(\"");
                        System.out.print(item.getKey());
                        System.out.print("\", b642Av(\"");
                        System.out.print(Base64.encodeAsString(AttributeValueMarshaller.marshall(item.getValue()).array()));
                        System.out.println("\"));");
                    }
                    System.out.print("ddb.putItem(new PutItemRequest(\"");
                    System.out.print(table);
                    System.out.println("\", item));");
                    System.out.println("item.clear();");
                    System.out.println();
                }
            } while (lastKey != null);

        }
    }

    private void insertV0SymData(AmazonDynamoDB ddb) {
        Map<String, AttributeValue> item = new HashMap<String, AttributeValue>();
        item.put("*amzn-ddb-map-sig*",
                b642Av("AGIAAAAglBLoUXuc8TgsJJlItgBh6PJ1YVk52nvQE9aErEB8jK8="));
        item.put("hashKey", b642Av("AG4AAAABMA=="));
        item.put(
                "*amzn-ddb-map-desc*",
                b642Av("AGIAAAAyAAAAAAAAABVhbXpuLWRkYi1tYXAtc3ltLW1vZGUAAAARL0NCQy9QS0NTNVBhZGRpbmc="));
        item.put("rangeKey", b642Av("AG4AAAABMQ=="));
        ddb.putItem(new PutItemRequest("TableName", item));
        item.clear();

        item.put("*amzn-ddb-map-sig*",
                b642Av("AGIAAAAgcjd91WBBFWPnrJxIJ2p2hnXFVCemgYw0HqRWcnoQcq4="));
        item.put("hashKey", b642Av("AG4AAAABMA=="));
        item.put(
                "*amzn-ddb-map-desc*",
                b642Av("AGIAAAAyAAAAAAAAABVhbXpuLWRkYi1tYXAtc3ltLW1vZGUAAAARL0NCQy9QS0NTNVBhZGRpbmc="));
        item.put("rangeKey", b642Av("AG4AAAABMg=="));
        ddb.putItem(new PutItemRequest("TableName", item));
        item.clear();

        item.put("*amzn-ddb-map-sig*",
                b642Av("AGIAAAAguXZKvYmUgZEOunUJctXpkvqhrgUoK1eLi8JpvlRozTI="));
        item.put("hashKey", b642Av("AG4AAAABMA=="));
        item.put(
                "*amzn-ddb-map-desc*",
                b642Av("AGIAAAAyAAAAAAAAABVhbXpuLWRkYi1tYXAtc3ltLW1vZGUAAAARL0NCQy9QS0NTNVBhZGRpbmc="));
        item.put("rangeKey", b642Av("AG4AAAABMw=="));
        ddb.putItem(new PutItemRequest("TableName", item));
        item.clear();

        item.put("*amzn-ddb-map-sig*",
                b642Av("AGIAAAAgyT2ehLcx/a609Ez6laLkTAqCtp0IYzzKV8Amv8jdQMw="));
        item.put("hashKey", b642Av("AG4AAAABMQ=="));
        item.put(
                "*amzn-ddb-map-desc*",
                b642Av("AGIAAAAyAAAAAAAAABVhbXpuLWRkYi1tYXAtc3ltLW1vZGUAAAARL0NCQy9QS0NTNVBhZGRpbmc="));
        item.put("rangeKey", b642Av("AG4AAAABMQ=="));
        ddb.putItem(new PutItemRequest("TableName", item));
        item.clear();

        item.put("*amzn-ddb-map-sig*",
                b642Av("AGIAAAAgYAai32/7MVrGjSzgcVxkFDqU+G9HcmuiNSWZHcnvfjg="));
        item.put("hashKey", b642Av("AG4AAAABMQ=="));
        item.put(
                "*amzn-ddb-map-desc*",
                b642Av("AGIAAAAyAAAAAAAAABVhbXpuLWRkYi1tYXAtc3ltLW1vZGUAAAARL0NCQy9QS0NTNVBhZGRpbmc="));
        item.put("rangeKey", b642Av("AG4AAAABMg=="));
        ddb.putItem(new PutItemRequest("TableName", item));
        item.clear();

        item.put("*amzn-ddb-map-sig*",
                b642Av("AGIAAAAg0iwjbBLCdtSosmDTDYzKxu3Q5qda0Ok9q3VbIJczBV0="));
        item.put("hashKey", b642Av("AG4AAAABMQ=="));
        item.put(
                "*amzn-ddb-map-desc*",
                b642Av("AGIAAAAyAAAAAAAAABVhbXpuLWRkYi1tYXAtc3ltLW1vZGUAAAARL0NCQy9QS0NTNVBhZGRpbmc="));
        item.put("rangeKey", b642Av("AG4AAAABMw=="));
        ddb.putItem(new PutItemRequest("TableName", item));
        item.clear();

        item.put("*amzn-ddb-map-sig*",
                b642Av("AGIAAAAgGl1jMNLZl/B70Hz2B4K4K46kir+hE6AeX8azZfFi8GA="));
        item.put("hashKey", b642Av("AG4AAAABNQ=="));
        item.put(
                "*amzn-ddb-map-desc*",
                b642Av("AGIAAAAyAAAAAAAAABVhbXpuLWRkYi1tYXAtc3ltLW1vZGUAAAARL0NCQy9QS0NTNVBhZGRpbmc="));
        item.put("rangeKey", b642Av("AG4AAAABMQ=="));
        ddb.putItem(new PutItemRequest("TableName", item));
        item.clear();

        item.put("*amzn-ddb-map-sig*",
                b642Av("AGIAAAAg66Vz0G8nOQzlvIpImXSkl+nmCpTYeRy8mAF4qgGgMw0="));
        item.put("hashKey", b642Av("AG4AAAABNg=="));
        item.put(
                "*amzn-ddb-map-desc*",
                b642Av("AGIAAAAyAAAAAAAAABVhbXpuLWRkYi1tYXAtc3ltLW1vZGUAAAARL0NCQy9QS0NTNVBhZGRpbmc="));
        item.put("rangeKey", b642Av("AG4AAAABMg=="));
        ddb.putItem(new PutItemRequest("TableName", item));
        item.clear();

        item.put("*amzn-ddb-map-sig*",
                b642Av("AGIAAAAgcSTe0npOBBtsxSN4F9mLF2WTyCN1+1owsVoGkYumiZQ="));
        item.put("hashKey", b642Av("AG4AAAABNw=="));
        item.put(
                "*amzn-ddb-map-desc*",
                b642Av("AGIAAAAyAAAAAAAAABVhbXpuLWRkYi1tYXAtc3ltLW1vZGUAAAARL0NCQy9QS0NTNVBhZGRpbmc="));
        item.put("rangeKey", b642Av("AG4AAAABMw=="));
        ddb.putItem(new PutItemRequest("TableName", item));
        item.clear();

        item.put("*amzn-ddb-map-sig*",
                b642Av("AGIAAAAgSAl9L6mP5YRNF8II0NsFXI9boH3t3lIKiF79HRTI/S4="));
        item.put("hashKey", b642Av("AG4AAAABNQ=="));
        item.put(
                "*amzn-ddb-map-desc*",
                b642Av("AGIAAAAyAAAAAAAAABVhbXpuLWRkYi1tYXAtc3ltLW1vZGUAAAARL0NCQy9QS0NTNVBhZGRpbmc="));
        item.put(
                "intSet",
                b642Av("AGIAAABAiev8e8T8ah3qIYPZ1n1KIxfRSzYIQuSnQt3bCSyuDHMf0iWGuHCe+n78jHZfaYwp5I1gB/6hZxtvN9eX64C+8A=="));
        item.put(
                "stringValue",
                b642Av("AGIAAAAw4kfr8MUHJOhcnCX8KwlBWMXckr09wIg+o4DsYPZCdAL5HIQDaeVpd+RFmWdM3eDa"));
        item.put(
                "stringSet",
                b642Av("AGIAAABA72pIpNYQv5fnqNV7hcxwtFM13JtmisBIRfW29VZVVgb7HQSV9ypTaDMwjqV0TyQOnEN/tDsHTfj0v4TvKYXYtw=="));
        item.put("rangeKey", b642Av("AG4AAAABNw=="));
        item.put("byteArrayValue",
                b642Av("AGIAAAAg5ZYktI5VjhPx0mN97APhxdi8u6vzDB/8O4XIDHVeJ2A="));
        item.put("intValue",
                b642Av("AGIAAAAgrfALMD+0hs7L1YzVVqLOraA4IOWnaOOTad7r7VErGm8="));
        item.put("version", b642Av("AG4AAAABMQ=="));
        ddb.putItem(new PutItemRequest("TableName", item));
        item.clear();

        item.put("*amzn-ddb-map-sig*",
                b642Av("AGIAAAAg+rzZO2IBAmjcybCXzbPtI3sF+u8f9GzLMGJGEPXofAI="));
        item.put("hashKey", b642Av("AG4AAAABNg=="));
        item.put(
                "*amzn-ddb-map-desc*",
                b642Av("AGIAAAAyAAAAAAAAABVhbXpuLWRkYi1tYXAtc3ltLW1vZGUAAAARL0NCQy9QS0NTNVBhZGRpbmc="));
        item.put(
                "intSet",
                b642Av("AGIAAABANLdRexuTujebNfVSeiYZ5RD6IZcmE1UDcvJ4PbiLP3Dng+MjwXWUt2+Eolw0HDm1Gd2rfITxs4Oor0ImZGlJBw=="));
        item.put("stringValue", b642Av("AHMAAAAMSGVsbG8gd29ybGQh"));
        item.put(
                "stringSet",
                b642Av("AGIAAABACZrDLG0nOoo9SDT0ib0zz7d0x5rN9UK8q7vhthuJxNJxo/3Qs+rjhYQYLI8DcLom35aTzsgyIIjyzFagyqtnBA=="));
        item.put("rangeKey", b642Av("AG4AAAABOA=="));
        item.put("byteArrayValue",
                b642Av("AGIAAAAgVVFzWfSD4PO/bD9g8RQOgCpZ+KlRH5+vdN2i1Wn9bDA="));
        item.put("intValue", b642Av("AG4AAAADMTIz"));
        item.put("version", b642Av("AG4AAAABMQ=="));
        ddb.putItem(new PutItemRequest("TableName", item));
        item.clear();

        item.put("*amzn-ddb-map-sig*",
                b642Av("AGIAAAAgiWWvGpcrzkUu241+NNtykoiWoeaSR3QHQMhHTmf0XAU="));
        item.put("hashKey", b642Av("AG4AAAABOA=="));
        item.put(
                "*amzn-ddb-map-desc*",
                b642Av("AGIAAAAyAAAAAAAAABVhbXpuLWRkYi1tYXAtc3ltLW1vZGUAAAARL0NCQy9QS0NTNVBhZGRpbmc="));
        item.put("intSet",
                b642Av("AE4AAAAFAAAAATAAAAABMQAAAAIxMAAAAAIxNQAAAAMyMDA="));
        item.put("stringValue", b642Av("AHMAAAAMSGVsbG8gd29ybGQh"));
        item.put("rangeKey", b642Av("AG4AAAACMTA="));
        item.put(
                "stringSet",
                b642Av("AFMAAAAEAAAAAT8AAAAFQ3J1ZWwAAAAHR29vZGJ5ZQAAAAVXb3JsZA=="));
        item.put("byteArrayValue", b642Av("AGIAAAAGAAECAwQF"));
        item.put("intValue", b642Av("AG4AAAADMTIz"));
        item.put("version", b642Av("AG4AAAABMQ=="));
        ddb.putItem(new PutItemRequest("TableName", item));
        item.clear();

        item.put("hashKey", b642Av("AG4AAAABNw=="));
        item.put("intSet",
                b642Av("AE4AAAAFAAAAATAAAAABMQAAAAIxMAAAAAIxNQAAAAMyMDA="));
        item.put("stringValue", b642Av("AHMAAAAMSGVsbG8gd29ybGQh"));
        item.put("rangeKey", b642Av("AG4AAAABOQ=="));
        item.put(
                "stringSet",
                b642Av("AFMAAAAEAAAAAT8AAAAFQ3J1ZWwAAAAHR29vZGJ5ZQAAAAVXb3JsZA=="));
        item.put("byteArrayValue", b642Av("AGIAAAAGAAECAwQF"));
        item.put("intValue", b642Av("AG4AAAADMTIz"));
        item.put("version", b642Av("AG4AAAABMQ=="));
        ddb.putItem(new PutItemRequest("TableName", item));
        item.clear();

        item.put("*amzn-ddb-map-sig*",
                b642Av("AGIAAAAgiZXCp3s7VEMYdf01YEWqMlXOBHv3+e8gKbECrPUW47I="));
        item.put("hashKey", b642Av("AHMAAAADQmFy"));
        item.put(
                "*amzn-ddb-map-desc*",
                b642Av("AGIAAAAyAAAAAAAAABVhbXpuLWRkYi1tYXAtc3ltLW1vZGUAAAARL0NCQy9QS0NTNVBhZGRpbmc="));
        ddb.putItem(new PutItemRequest("HashKeyOnly", item));
        item.clear();

        item.put("*amzn-ddb-map-sig*",
                b642Av("AGIAAAAgzh74eH/yJQFzkm5mq52iFAlSDpXAFe3ZP2nv7X/xY1w="));
        item.put("hashKey", b642Av("AHMAAAADQmF6"));
        item.put(
                "*amzn-ddb-map-desc*",
                b642Av("AGIAAAAyAAAAAAAAABVhbXpuLWRkYi1tYXAtc3ltLW1vZGUAAAARL0NCQy9QS0NTNVBhZGRpbmc="));
        ddb.putItem(new PutItemRequest("HashKeyOnly", item));
        item.clear();

        item.put("*amzn-ddb-map-sig*",
                b642Av("AGIAAAAgHR5P6kozMSqqs+rnDMaCiymH8++OwEVzx2Y13ZMp5P8="));
        item.put("hashKey", b642Av("AHMAAAADRm9v"));
        item.put(
                "*amzn-ddb-map-desc*",
                b642Av("AGIAAAAyAAAAAAAAABVhbXpuLWRkYi1tYXAtc3ltLW1vZGUAAAARL0NCQy9QS0NTNVBhZGRpbmc="));
        ddb.putItem(new PutItemRequest("HashKeyOnly", item));
        item.clear();
    }

    private void insertV0AsymData(AmazonDynamoDB ddb) {
        Map<String, AttributeValue> item = new HashMap<String, AttributeValue>();
        item.put(
                "*amzn-ddb-map-sig*",
                b642Av("AGIAAAEAVRRX8l/eqIeMo7TvQbHI+0Zfh6tbwT5rFJ2zTLYoloudkb8WcBjcHuHEGUhFia6lSKOXwU1cEi/dT4YbQUXf2vzVTxS7jDstYHwHxscVPYNKp7FKzrG/Rym2lF1D78cTn46Zu2/XPw/JgTUhL0Ar7nmmDjUONzzd41QZGr45PFtgBZzGSHyyIpWU2+TRA87quKL71YnrzfbfWoIutJLQ8lAuGlx/gm++09c8PCL60CwUGl6moaVzSYpu/zR+1lxFZ67sWnNrxlsezsQcWUbPJKgeaHfeKDxSevaALTS9dCAjSlE0Sv7XbsdjxW2huNPcPTQCOcqUtetDJ1W2GLa1mg=="));
        item.put("hashKey", b642Av("AG4AAAABMA=="));
        item.put(
                "*amzn-ddb-map-desc*",
                b642Av("AGIAAAHzAAAAAAAAABdhbXpuLWRkYi1tYXAtc2lnbmluZ0FsZwAAAA1TSEEyNTZ3aXRoUlNBAAAAEGFtem4tZGRiLWVudi1hbGcAAAADQUVTAAAAFWFtem4tZGRiLW1hcC1zeW0tbW9kZQAAABEvQ0JDL1BLQ1M1UGFkZGluZwAAABBhbXpuLWRkYi1lbnYta2V5AAABYkRuNjVvVFdnenJYQmV5bGVwb2x4bm93TTBxa1AzYTRHdjFBS0pHUkhOK2hSMW8wL3ZBM1pEVUowRTczWk1HTGZ0UUtQSjQrbkRqd3kNCkQyTmkwekNlTjVaMnJIOW54cU1TeGI4VUlDNGNWMjRJYVhCa3hUU0IrRUN5b3VYVzBINnhBbFlGdzhZNTZvTEhYYjNqYkdWRFZyUmoNCjBoby9ZZ3FDTjRVZmhFUmxKN2hhTnZMTmVWNXBMa0FLRWlPa2cyMWZEZFBXUWZaYllMMGhYL0RtaVpLWVlSU0N1aS9KcWFudFhkREUNCmppMkZqUVlCRnp6cmxkTkFYckRKcnBFSk9STkRhRDJ3UXpJYVpFY2ZBY1RlR3oyUzM5a1Q2azN2MlBIWndaRFdKUVdKMWcxc2pvdWcNClNVUnZHVkZ3UThpUW5XdmNPRDBRQkF0aFhqZVhEOEd6eGZxSFZnPT0NCg=="));
        item.put("rangeKey", b642Av("AG4AAAABMQ=="));
        ddb.putItem(new PutItemRequest("TableName", item));
        item.clear();

        item.put(
                "*amzn-ddb-map-sig*",
                b642Av("AGIAAAEAMG6vTV+uPAaPmZIGR4I4DbUwIUmivEZQ5sqpK83hue0SArv2a9TtlOTIighJa3b+u/LR/0kxm2Jbx5nqrI7oT0eKSjqJYk1S3w2W/JDPzyk4wwwSoOKH4TLq0KxwXE7QEM4aS5hs92ja6jKPIj7nEJKYOOwHdCdu3Qu2SBmY0VWyj+pUohZv5fzDD81nMeCWU7KmtFsXfKAFFHM2ufCWywXRBXKfYTDPYR87+bfNvbw5W/FmDeu9pdpCIbV66yR3pl4d9+FLoDqbS5yQjKzDI+X5Z90FBaW1xaPCKLcp2l9tRq8q8hfvyXZXrJVisu+/igjqpZ3Tszj9XBmmqLFo/A=="));
        item.put("hashKey", b642Av("AG4AAAABMA=="));
        item.put(
                "*amzn-ddb-map-desc*",
                b642Av("AGIAAAHzAAAAAAAAABdhbXpuLWRkYi1tYXAtc2lnbmluZ0FsZwAAAA1TSEEyNTZ3aXRoUlNBAAAAEGFtem4tZGRiLWVudi1hbGcAAAADQUVTAAAAFWFtem4tZGRiLW1hcC1zeW0tbW9kZQAAABEvQ0JDL1BLQ1M1UGFkZGluZwAAABBhbXpuLWRkYi1lbnYta2V5AAABYmovWUFVaTV5N0tRUWQrVFl3a296ZURERXFuY2RpTWFWc3dKYmI2dERuM0VTeHVaRXpZempOMlN3dEJxSENia1NrZmpGMGZBMVNvdUQNCi9Yc21iRTJGaXlOSWRTZE5uSFQzak5xN0FHOTMrVG9rUCtrREx3Y1Y5VFJYMUNwK1FIbk5TVzN1ZmxqbGlKTDFPQTZCS294bHNmNEoNCng0elNvck8yUHhac1ZDY2g2LzFSNU8zNHJqcU1QZUxlTHBrYmpUcS9xK1RkNDNxODJoeUVQejFTdHo2NU9xUVkrellTcjlZOHp5WTANCmkxNWlwcGVyRzQ3aUIxc002aXV3YWhxNFBVVEdkdTZiQkRiQmRxb04wTFpwUldVMTdueDRHNDRhTUJlZFNHODk0NXpiVkUrRE1hNEINCitORUpYeDBzdkxmZXM1aEJIMUNBQzFyZml2ckFCaDRXQndLYTZ3PT0NCg=="));
        item.put("rangeKey", b642Av("AG4AAAABMg=="));
        ddb.putItem(new PutItemRequest("TableName", item));
        item.clear();

        item.put(
                "*amzn-ddb-map-sig*",
                b642Av("AGIAAAEAed4gAI82hqUpvoUH/glIJXIbasq7CDMbcfm2u/fojO+3FsujnsCRCcIJZIe6ny3ExNC/o272WzUL+Tw1tFnM0VYcS1aAgpdJiTyX4LFPp4uJRlutcxDWCOBpAVh+Ma/oIQDAgxlm1EOcKiWyxhyXm3Bjm8c//rV/YyMkm7NpqK99zCfbgnwI/ezGvEaJe5L3N4eLZBAV9BG7B6if9uvSvCWh3NABr9XNeaXLCHC300ENCk8iUNJJASi1sGQnlTR186Ix8s4DPCfZJbNwWlHrbupgmBq+AZRffbU059QrLfvzdxpaRtHIlDxQwmvk8C7EU2kUuLGyEA8XSdiT5y2fRw=="));
        item.put("hashKey", b642Av("AG4AAAABMA=="));
        item.put(
                "*amzn-ddb-map-desc*",
                b642Av("AGIAAAHzAAAAAAAAABdhbXpuLWRkYi1tYXAtc2lnbmluZ0FsZwAAAA1TSEEyNTZ3aXRoUlNBAAAAEGFtem4tZGRiLWVudi1hbGcAAAADQUVTAAAAFWFtem4tZGRiLW1hcC1zeW0tbW9kZQAAABEvQ0JDL1BLQ1M1UGFkZGluZwAAABBhbXpuLWRkYi1lbnYta2V5AAABYlEzNXRBaXlVYWc2VjZpTGFPS3kxS2pJZ1AyekdydEI3QVpvS1UxNmVpbHF3WnN0emJIK3hwYkRYZTQxRVlIRjIwL1VrdVAxeWdwVG0NCmJTOEM2VjVVMHl3dnRaOE5CSmV3ZGFIeXNMemVZTEhiMmNaL3VrTWg4dUFXRjhIRjJ1NGF5eXVKZkZtcldIbGRMTGVRdENUUVA4eEUNCnFpMEtrcU5lcURGTitEeDVNeFpxaVhUd0MycmptT2N5MVBiOTBCQWJLRFNLVERsLzRNRzhWcVBCUjFhMENFalExL3dwOWRSdS9FRUoNCmN1eUhQdjFHVmp6YmFNUWRpem0yWmhOTnZvRWpCUlJkRFgyRGVDU1hNcjFIVXFnbVRuSVoza3l6SWtIVG5NNjl4MGErSDltNGZadEgNCnM1ckxmQjd2R3ZlQjgrQTRLdURTVDBueksrWHA3Q2o5YzIrZ1hnPT0NCg=="));
        item.put("rangeKey", b642Av("AG4AAAABMw=="));
        ddb.putItem(new PutItemRequest("TableName", item));
        item.clear();

        item.put(
                "*amzn-ddb-map-sig*",
                b642Av("AGIAAAEAMaO/4MFm20VFjw2ER/jpwi6iR2VBYKp+uwdJH+/CZv1NlwMDp+9t7MHu9DArLIzQlHjUQ905a8FV9LeNHcDD29CNDXz3u0I6u7Rznhoa78N6fO08aDdHn+MtLzoZaKi7dpJ1M2xNzAM/3x2dTkLiCGKuAOnpmk4SSG2vKu1OssM4e9VTwWgdWgUBHyMef38fEoT55XRy67phr4e77kVesV+X/lM+JudGuzxZgbrFsFVgy98DQ2SJF4gpNKkNOeWKFIomT8bEukxECfi0Vyk/m7PSMKgvF5JBBNQYEt7HXRUo1lVmUc7WvBHYU4dVkz2oQZn06F//IAZo+qsmqOM12Q=="));
        item.put("hashKey", b642Av("AG4AAAABMQ=="));
        item.put(
                "*amzn-ddb-map-desc*",
                b642Av("AGIAAAHzAAAAAAAAABdhbXpuLWRkYi1tYXAtc2lnbmluZ0FsZwAAAA1TSEEyNTZ3aXRoUlNBAAAAEGFtem4tZGRiLWVudi1hbGcAAAADQUVTAAAAFWFtem4tZGRiLW1hcC1zeW0tbW9kZQAAABEvQ0JDL1BLQ1M1UGFkZGluZwAAABBhbXpuLWRkYi1lbnYta2V5AAABYlZ5OTRVdHkweHVxUlFtNWl5S3ZkM2NNZHhPalBWSlBsWWZHdDVJaStseFNwb2pnKy9XRjQyNmkyWmVZb1Y4a1BBN284cnRXMlk2UHUNCnRJZzFtc2gzdDROYzZGTnJPOFNkR2JxZFE4TVdmYWVHSWdiaElmWmM3NVFQaE9UWWdSNytEOG4rbnpwZ2FqUDNiTWMyYkRDK1lac1INCnFmbnhTVDhYa2tGRGZqWFVlZGlld2VrcXloU2NUc0QrTkJZSUxEWU1vWCtoNUZZYTgyQWRMSWZNTHlmS3Y0Y2FIeTE4YklzcFM2TVMNCmJjcFJkcnBUNGI0M2c1Q295UTdLZTNwZHhQT3IyNEpKbHlEeWhDeFpLY1FUNi9GWjNMeDl3blBONW9IRXZaMEVqc0R5VUREeEdwOTUNCkF1TmVCbmN5UTRUTEhQTW9RSE9kSklnS3VvTUsvZ0xwUzQvamJ3PT0NCg=="));
        item.put("rangeKey", b642Av("AG4AAAABMQ=="));
        ddb.putItem(new PutItemRequest("TableName", item));
        item.clear();

        item.put(
                "*amzn-ddb-map-sig*",
                b642Av("AGIAAAEAfq5jMK7LBRwa63vh+Unxjxxuj8ugx/l0jqRalmWNql+k/RTz3lxsNCTFh1svGTP4QZTLL/GghdZGmGH2Pb82M45ExGsvZoVzkdQ6Gc/y8NNCMkD98pZyYeWchDazrqC1EnB+IoYbuG5vQF5vCwR2jEfd42bu+YnPMy3ackMEF9fDamQdHsAwfDDFsshmePA0Q4RMOaBUu48YhrDhSYPXH2DAv8lwPqh4lWGOrtalV5MFCvVzFO5ss47XDeI5zjafkwoJQPU5b44cvvLXeq56p0cWn9uFt2XMZ3HBHxDOOOAUkqNKShlaQ3m39SdU58fN50MLrc3G3mUjbttFBBE5AA=="));
        item.put("hashKey", b642Av("AG4AAAABMQ=="));
        item.put(
                "*amzn-ddb-map-desc*",
                b642Av("AGIAAAHzAAAAAAAAABdhbXpuLWRkYi1tYXAtc2lnbmluZ0FsZwAAAA1TSEEyNTZ3aXRoUlNBAAAAEGFtem4tZGRiLWVudi1hbGcAAAADQUVTAAAAFWFtem4tZGRiLW1hcC1zeW0tbW9kZQAAABEvQ0JDL1BLQ1M1UGFkZGluZwAAABBhbXpuLWRkYi1lbnYta2V5AAABYkl0Qkp1TnJxeFdTVWk0OGVWR2RFUS9RdVpzL0JSWnlpTVYreVBkaFdIemNpZk9QbVROWndFckdybGhuS1ovZ1BWT2NzSlRGWHMyelcNCmJ1Rm12cVdZdlVYN1lnaDdacjJSQm0zbGRHQ25WRTFjZEluak4yU042clh3S1dzbzF2Z0RpUmJRcUF5TVpMS2dwbTZZTnlFZnhjSzYNCkVpZGNpKzhWRVlHdkYzYm5mVGtoMWVmK0RXbHYxTWxYSnYwcGRSaXFmU3dnZThjNmxGTUs2M2t5Y2JFWTFpNXV1NWZubEIydURJTTgNCnRrNUhDV2gzQlVoZ1B2Z01zQWM4SHN3QVNyazcxWFZlQzNXWVR1dTlTQVVOUS9Va25IdzNvcitvT09POW5YTXVEWFFWbjF3WGhpUUQNCkFxNWgzN0hULy8vYmZDUDlWQ3cxQXRwY0ZKRXNHNzViNjg3N0JRPT0NCg=="));
        item.put("rangeKey", b642Av("AG4AAAABMg=="));
        ddb.putItem(new PutItemRequest("TableName", item));
        item.clear();

        item.put(
                "*amzn-ddb-map-sig*",
                b642Av("AGIAAAEAraKHapJyc7wtw9Qzbr4c4AbRlLAT8p0rkrN+gm3JFSJwFLHtf6dHBQv9tveVRNo4VMeV+PJDbWDcPDEivK4Vq5N9BAlveRSx+d9Mj/ueK323VUIGynQwdI2PO0J4pncTvFIH/VMauMcCItOlmaOV/pKogUIYLqEGdgqPd5M6TuL0Gxki9i9lzZOg10yJZjTIg33I4L1C04xQVZ7c9gcyQB715y0TwF+0oXs1EG2KtUdF2oS2yqCb67v226gdj5aoFNUzfijy7v3s3cRMVA0fQKwpda+d9Rj5NzkvwBo43oKFFh58tl6FbRa3nN9Jj9cxWGtTSIlVd9RQ+vttzObdIg=="));
        item.put("hashKey", b642Av("AG4AAAABMQ=="));
        item.put(
                "*amzn-ddb-map-desc*",
                b642Av("AGIAAAHzAAAAAAAAABdhbXpuLWRkYi1tYXAtc2lnbmluZ0FsZwAAAA1TSEEyNTZ3aXRoUlNBAAAAEGFtem4tZGRiLWVudi1hbGcAAAADQUVTAAAAFWFtem4tZGRiLW1hcC1zeW0tbW9kZQAAABEvQ0JDL1BLQ1M1UGFkZGluZwAAABBhbXpuLWRkYi1lbnYta2V5AAABYmdvZVVuaFU5YTBoR3hiWVl4MXZnckE0MFcvYmRLTjEraHBvUi9wazZsOVpXM05kNlV6cmhlR3VWN3NCSG1sSUVqcXVCemIyd3FnTncNCnFCRy9hZ3FvZ2lsdGQ3ZUZpNmdVdXQ4N3MvMm5kMjZFL1JiRERPd1QvUUxCYzRGZWtxSlEzTmZzaitPL25VeDVWeVJKTU82ZStHOVENCjRYWWRXcG5OWmlmMTRVTWMzZlR3YlBmY3BzYWFUQm1VTzJ6WS84d0lhbzlNb1hPYXd3ZVlydWZJSXdZZEp5bWhTTnIyZFBqTUVVWUQNCnJjOW1oOXZZQklTRWIyZnNOTFBObWFRL2FKK25NK0VBVGN2SDJVWTBCMjU3a2dVOENqOEhhbG82VGswVEZ3ckIxVXhoVkRvZ0dUZHUNCmdiTHpFMHFjbDZNbHkwNS9wT1lLeU1rcGV4MzM5M1Rzc2xRR0pnPT0NCg=="));
        item.put("rangeKey", b642Av("AG4AAAABMw=="));
        ddb.putItem(new PutItemRequest("TableName", item));
        item.clear();

        item.put(
                "*amzn-ddb-map-sig*",
                b642Av("AGIAAAEAMlADNyM2Rd+jSXzd/NgK53qnNIWrjOswmITkLKy6wmuP7tyYZZfdz/yN9rv/AeaDF0SKxQiTkIuWxtibyATiEFLc2DdulIx8Kl2ZydWSgvEI8ZCrKDNjhX8auceL2XZwqUQEWgNIoSRj+TpXZNwxygg0ZyT9d+PP8RT3yM64/9A2nW9WHMWK/ASwGJVHo1dlDzdspvcUCEtkO7U4ey9q25HX7YDx5p+yMxUH360fDuDYnXIdMyOSwPFO6LkcBpkxWSHsgB1jSZ9bVVceXi+mM3sUL+aLkUd/sP9Yl5/mOKASpJezNKcetAdSaC7VSKJ1PMbcEDSmK6XqblnNGF1L/Q=="));
        item.put("hashKey", b642Av("AG4AAAABNQ=="));
        item.put(
                "*amzn-ddb-map-desc*",
                b642Av("AGIAAAHzAAAAAAAAABdhbXpuLWRkYi1tYXAtc2lnbmluZ0FsZwAAAA1TSEEyNTZ3aXRoUlNBAAAAEGFtem4tZGRiLWVudi1hbGcAAAADQUVTAAAAFWFtem4tZGRiLW1hcC1zeW0tbW9kZQAAABEvQ0JDL1BLQ1M1UGFkZGluZwAAABBhbXpuLWRkYi1lbnYta2V5AAABYnBSTWdtTmwvdjl0QUtOUXdhVjNCTVRaU2pVSjIxd3d4UHVWcU9wLzBtRzl1c2ZXeHU1WEJMQ1hqOFNtM2RaalBEbzJwdldYeEFhNVANCkxBZnBxZG1sVUlOVFJzVG9PaWdrTWFVaEx3bEwyTEZtTVpDUXJPZElPdWV1aFhqN1NvblUvaXRvRlZTYTBxU2hNZjVsbld3OHVGWlkNCnNmUjhXM3B2NDNuRjc3ZHF4SU1KWnkwR1kvdENjeFNtcUZBSkl3YW5PQVVZVXVPQWo4Qmpld3Y4U2lkTVFTWkExY3krV0NkdHkrVFQNClg1cUJubDFvNHI1c1NhSENjNHU0OFBkcGpmczF3ZDY5SVRQMnFCZVZBM3hxVFMyejN4bkJ2Z0VEZWtlWEJlNzE1Q0JvM1ZsM0RVSW0NCndkbVppejdKTEVUYVQvVXpmVGZ1NlVGYUZzR2Q2ODN4dzgvS0hBPT0NCg=="));
        item.put("rangeKey", b642Av("AG4AAAABMQ=="));
        ddb.putItem(new PutItemRequest("TableName", item));
        item.clear();

        item.put(
                "*amzn-ddb-map-sig*",
                b642Av("AGIAAAEAm2vH2mT8PqjrYI2ljgT6HlMeXhNylQvKZQmz8JkoLr50ks+SZ7WAQ/u+l6OMowXQ9pIWadzSsDiwX47UJTcE2gibTVfbBj8XTnvxOerQeYKm1wJ6rSpFDCt1I75xmbxr3GVbD+eCFS/kPPLR8U0uOVW1RY3vhg2qlrOFVYeOEEWQK1Ds7UF12EQm51ClL+UwH1RoPo/SCABqkiU998a4hvWV57TIefrOtrQBs//ZOGm2BswAtnVjmOd9OZmmnwyVQC6/i50YJOcaON1qiW5+Yl9o8gfE7kRXJ+iCuoOzT4iR2i7Z0xOsMuKme1M1ZNBirBNSpHKvJnTpRJ7K2fzXQA=="));
        item.put("hashKey", b642Av("AG4AAAABNQ=="));
        item.put(
                "intSet",
                b642Av("AGIAAABAw1+zjeZeeNkjUAgxg6HrlPi++MwbD8DSvM0jSvQQ+lQyzmVEB5IT5/6CoEtPVMasQUVTE/iODio0Yjkdek6vcA=="));
        item.put(
                "*amzn-ddb-map-desc*",
                b642Av("AGIAAAHzAAAAAAAAABdhbXpuLWRkYi1tYXAtc2lnbmluZ0FsZwAAAA1TSEEyNTZ3aXRoUlNBAAAAEGFtem4tZGRiLWVudi1hbGcAAAADQUVTAAAAFWFtem4tZGRiLW1hcC1zeW0tbW9kZQAAABEvQ0JDL1BLQ1M1UGFkZGluZwAAABBhbXpuLWRkYi1lbnYta2V5AAABYnJ5ZGJGRzVFbWkxVURXS1htTEdQZ05zaXh0SURPYXd4Ty9yVXlsWVFTTFduYjB1NTlyM0xWdzVlcmx1Rk5YdC9mS1RYQWdOVFhNeDANClhiSm9Oa3BvcFRDWFlQRnFPSkVINWwxNnBDWXpyU1N3ZXJWdWlRMk5ZcHJ0KytwNlRZOWFKTzZvOVhEUW4wVzNEQmgrSWVUMDEzcDYNCmVCSnhyTjNHRzM0ejc3RHhUZnJRWENpVFp1c2E4WFp5akptVkh2eTdNMmxUdzlMUG00SjBNZ1lHNjBKMUFvd2N3ajdnSGpmaXRuNnkNCnhjL3RqUUg4VVBjcnBvME9HSFpjU0htZGhadlNtSzJnRlh4WkFuVFpLZ2hUL2VxRHFCODhISWJJbzl1QTBzQWdMN0tscjY0c3RvbEUNCmc3TkVhNzdqMGFpd0RKVmhzMk5ZTkdWcjg4UWgzVVNrZmk4akpnPT0NCg=="));
        item.put(
                "stringValue",
                b642Av("AGIAAAAwWm3eBDw275auRay6J0l2m3KEn9sDTPC75ESTTKaE0mJXasDHiYEWWMt2ubWIMrYv"));
        item.put("rangeKey", b642Av("AG4AAAABNw=="));
        item.put(
                "stringSet",
                b642Av("AGIAAABAU6yqvtM7vMRXHD9uugPaJp68Ro9jNhoUyKwoItVSvkZDPNypGFXX1L42AuBQbeq4km4kXBwPbnLRfqoPVUG/tw=="));
        item.put("byteArrayValue",
                b642Av("AGIAAAAg5d/ldqZexHMg6B/GfymHSqxoSFNG3hJKVsof8P6fIgg="));
        item.put("intValue",
                b642Av("AGIAAAAg4YeimDgZV76L9rTz+0Me0rXVvSvlPt3W0+1ah1roEqE="));
        item.put("version", b642Av("AG4AAAABMQ=="));
        ddb.putItem(new PutItemRequest("TableName", item));
        item.clear();

        item.put(
                "*amzn-ddb-map-sig*",
                b642Av("AGIAAAEAjKVKU8uHbhAg8vlU8WqK3qIss6XKPJQXATVwFlkqw5N7RMj0yjQWQ5pJC81sdkXp3NmIgF9Wnavzl5TEVB6R4v/cwxT85ih/kMN7NDOXU5OEkQUlzCRCZ3U6wVvWgFbbI68r42LNPav+uuWBB2/cp9Uu/4VbsOQC7IjEdWIPkir+5BP7HBFg78cs9YgpkDuw2J8+4KLj4z5CsSW6dPjhmbPolKmhn8DinezJ6bHpRFmP0ry75HxMUTu2wInwHD0mCpK1TXWJ3t8V1+UJkNHHpD6j78UhNH9Ky2h9pgj+7Gml0pnZ9t0skUCXNcBLf0Pj3RsqvQuYrU6f2tV8DDxm8g=="));
        item.put("hashKey", b642Av("AG4AAAABNg=="));
        item.put(
                "*amzn-ddb-map-desc*",
                b642Av("AGIAAAHzAAAAAAAAABdhbXpuLWRkYi1tYXAtc2lnbmluZ0FsZwAAAA1TSEEyNTZ3aXRoUlNBAAAAEGFtem4tZGRiLWVudi1hbGcAAAADQUVTAAAAFWFtem4tZGRiLW1hcC1zeW0tbW9kZQAAABEvQ0JDL1BLQ1M1UGFkZGluZwAAABBhbXpuLWRkYi1lbnYta2V5AAABYm5TZFVpMlQzWjRNRjJQUjJVUHRweWZIK25CZU1wUEdKbzg0TUJneFVWek4rOXFvNStvaGRXSEp2NEsrTDRwRUJJVGVZTEllV3lGVmsNCkdEZ3dNTk5ZanNmYjgxVy9iekdpM3pzclFjUGFRTi9JZ2RaWTFEdFFKbkFvRUZSbmJ0SGkxaG5pSkdiUlljc3BOanY0NXpaOWd3K2cNCitMN2dnM1Q0WEY1dUg1QUsxY1lLUkVWZUJKb2RFdU43ZGVGZkRWZ3A1NjR6cDA0QXVaTldqcENmYmNOb0dsenJaSGtIZkhtTTVtQ0cNCmFPaUpzc2crZmM0Nm5tLy9BdUc1eUs2MnV5cyt1QWJ1d2RYZlNhUDZSbjY3ZXkrL1BBUVA3SUpYRWVKYndEb1U3djVTcngrWWEyaDYNCmtYbUZFLzhMbVMzM3Vad0lqeW1nNDRWTjE5cERYZUd4NWRLU3Z3PT0NCg=="));
        item.put("rangeKey", b642Av("AG4AAAABMg=="));
        ddb.putItem(new PutItemRequest("TableName", item));
        item.clear();

        item.put(
                "*amzn-ddb-map-sig*",
                b642Av("AGIAAAEAhALCfRcpQ0FpzL1HJQQk5WbSRKN7pD9C1vkkzVlA74pYCsBmHm9GAKTrO7Thyw58BpZtFX8wiRO1aTkPpL5L1oh9rQ9+TlvMv7+MbBB/WwMnx57FbV9I4Cu5mMFiDXpTt7k8I+QEFRJwMdzs5HSv0bjz3FyOBbmXFqkMQaak61nz2KoM3kwUd38jb7sU+calk2Chlh5Rh6Y2JFgJ3L38h6DPrbsB6Hxqx1q8+vod80XWw2IyYmqZ2EKQte6Ot21AcDv3ECm2+XQZsFHAQTHJUSlFAilkhGv1FEtt0NwEUCsgR7Z6YE4gi0JCQ0bdQuVY7XrlY0A6ywT2+wkHBtYI/Q=="));
        item.put("hashKey", b642Av("AG4AAAABNg=="));
        item.put(
                "intSet",
                b642Av("AGIAAABAmMIiJONTWUfeTaBy+FgY9TkJadGmsLe4X3qaJ8H1pnebXSz+GiZKhz9P9UfTgkpmYdxEyIqK9Pyq3zMtPDoOXw=="));
        item.put(
                "*amzn-ddb-map-desc*",
                b642Av("AGIAAAHzAAAAAAAAABdhbXpuLWRkYi1tYXAtc2lnbmluZ0FsZwAAAA1TSEEyNTZ3aXRoUlNBAAAAEGFtem4tZGRiLWVudi1hbGcAAAADQUVTAAAAFWFtem4tZGRiLW1hcC1zeW0tbW9kZQAAABEvQ0JDL1BLQ1M1UGFkZGluZwAAABBhbXpuLWRkYi1lbnYta2V5AAABYk8ycmIwcEZMWlV5cUQyT1JDM0xYMkdDZWxjNWtiTjJPaU1wYWxTSVNzVUhnV2ZuVjJ0ZmVoUlo3VGZPZEhrYXpDUVBzNDlQWDN6b1MNCldlV25NS0NjQ1YzS0g3NFN4V3VQTkVhZlVBRVl2RTMvRUtBdmhWc0t2K01tUWdYd2pJckJNUGN0THBKcUtOVU9hUWxkR3EzVnZ0eXYNCkFqam5CUktzTU13RVFJY2VMbUxWbTRkSjJhSTd3STBDL0pZZmtJU090MWdqY2gycTI2c3hiYzYzYXhwOEtnUWg3dms5WTQzQVpMeTkNCnhVL3NJNHVkck1DN2hOLzc0WEZkemdWbU1vbHk4S3lUUklCK2JTN2ZwV1F4RE9ESk0xK1RhNEZPd1Z2VHQrTVUrdUtCQnJ4aVkrT2QNCnkxYVVRSlVXakVHM3VSNW1raFdtVHVtemNYZm8yakNUNlJIYWdBPT0NCg=="));
        item.put("stringValue", b642Av("AHMAAAAMSGVsbG8gd29ybGQh"));
        item.put("rangeKey", b642Av("AG4AAAABOA=="));
        item.put(
                "stringSet",
                b642Av("AGIAAABAAbnuuD5NoWcpbMV05yWaeXoq/UDb6VcAxqC6JMaFFktVEYp3BWjmqtyFRrt6Gc0t03nzLvPOWs6Uj6k33J87bQ=="));
        item.put("byteArrayValue",
                b642Av("AGIAAAAgVkfWaVfJ9aQxJWHKPpPFyrAvQ3Eogu4H04hNNcG+bno="));
        item.put("intValue", b642Av("AG4AAAADMTIz"));
        item.put("version", b642Av("AG4AAAABMQ=="));
        ddb.putItem(new PutItemRequest("TableName", item));
        item.clear();

        item.put(
                "*amzn-ddb-map-sig*",
                b642Av("AGIAAAEAUKESqnTKdCqAtM6aDkJGg068ssNWFv811njBVuRK7mzVtmIG5OxLQKr8ycBf/Zm3j2fDnkeLnZwc/Fya9XCTygte4yy1QZSywrSb83uhGFlmLsjGOKcE5ZTMPEMb75+I+8I8OQ3ggfM3EnyaTFQCIfeY+3antQ3augrWioBaoJ3VpoUU+RSA6FOrlVtd01qNO2ZOXCfcX5soh2r60FXZ3fdJZJKvO61xkf4nlZJQkc175bsV8KRHh+125a/KETb+3Gc8uL2aRFBO03fuSCHS97YN7nbevtzM/WdqfXh83N0sBIibHhY73xd5n1sDwKhn9D3madRlzlj6GgwiY6wOqQ=="));
        item.put("hashKey", b642Av("AG4AAAABNw=="));
        item.put(
                "*amzn-ddb-map-desc*",
                b642Av("AGIAAAHzAAAAAAAAABdhbXpuLWRkYi1tYXAtc2lnbmluZ0FsZwAAAA1TSEEyNTZ3aXRoUlNBAAAAEGFtem4tZGRiLWVudi1hbGcAAAADQUVTAAAAFWFtem4tZGRiLW1hcC1zeW0tbW9kZQAAABEvQ0JDL1BLQ1M1UGFkZGluZwAAABBhbXpuLWRkYi1lbnYta2V5AAABYkRjTHUzdlByS0xiN0g4eVZOTkJQMFZ3dXpGWU1ONkpDb2hCT3NscUpYN09wSGdORFgwNUhEZlRMNGFBRGFmamVvMUMrQ2pxZ0JLZVgNCkU1UTE0aTYxN0JyMDQwOHczRlNhdnRObkI4eTZEVXY3cmhSSElBMThGbTJqWVhvMkFZRUlXbzZFRkR6TGh4RUtIV0pmVnppYzZXSzcNCkc2L24xUFUwc2pEUFRtNC9DdE1STWRnbkk1SnA3c1BBSVFOZ0M1M3JPY0FaS0p0ZEU1UmJ1TllCTzJZaTE4eGVPMUNNUVVnOFlWWmkNCllDM25NQlVjZitSTGk0NE1IZHUzMnNCMHFtMGZoZnZ3WjlMaE8xL1VaWlRmK1ptejRFT3h0cDMyaTI5K09LQmxnUlFmNzZRaExGaEYNClVlZVhsRjdZRytKSG9iUTV4dlBzbmxXQUY0T3FaOXJwWGVIQUxnPT0NCg=="));
        item.put("rangeKey", b642Av("AG4AAAABMw=="));
        ddb.putItem(new PutItemRequest("TableName", item));
        item.clear();

        item.put("hashKey", b642Av("AG4AAAABNw=="));
        item.put("intSet",
                b642Av("AE4AAAAFAAAAATAAAAABMQAAAAIxMAAAAAIxNQAAAAMyMDA="));
        item.put("stringValue", b642Av("AHMAAAAMSGVsbG8gd29ybGQh"));
        item.put(
                "stringSet",
                b642Av("AFMAAAAEAAAAAT8AAAAFQ3J1ZWwAAAAHR29vZGJ5ZQAAAAVXb3JsZA=="));
        item.put("rangeKey", b642Av("AG4AAAABOQ=="));
        item.put("byteArrayValue", b642Av("AGIAAAAGAAECAwQF"));
        item.put("intValue", b642Av("AG4AAAADMTIz"));
        item.put("version", b642Av("AG4AAAABMQ=="));
        ddb.putItem(new PutItemRequest("TableName", item));
        item.clear();

        item.put(
                "*amzn-ddb-map-sig*",
                b642Av("AGIAAAEAfuTnJmdj2YTv+7PSKT/hVA/HaYJZCuXquvdCFafntAtjNqcQI371menVgbKHLKYZsqaTrCEHskNESd8qzXjJup2uOYdJOl01OKc0qasI+a0XwQspILlhIBo+TJ91/XyUTbqvRExXv+yJ3S1AY7vQmqIIumzy6kcVk0IR0pJjyqCKLbWumJdR+NgITuaowVMGi4BrjE8W3/ucJnB1yh1MZ5kQlINCgW+80MdEmCtxkZ9Lq40CMlhtXoXXXKNtZ5vh/TK0IDEoDMBQKMv3/MoSDxmRjkwCVRjJaD4ofpbmOaubInuVhMMQ2gPkQ8oxNRaNxoqhMv44rgry/sThLLOt7A=="));
        item.put("hashKey", b642Av("AG4AAAABOA=="));
        item.put("intSet",
                b642Av("AE4AAAAFAAAAATAAAAABMQAAAAIxMAAAAAIxNQAAAAMyMDA="));
        item.put(
                "*amzn-ddb-map-desc*",
                b642Av("AGIAAAHzAAAAAAAAABdhbXpuLWRkYi1tYXAtc2lnbmluZ0FsZwAAAA1TSEEyNTZ3aXRoUlNBAAAAEGFtem4tZGRiLWVudi1hbGcAAAADQUVTAAAAFWFtem4tZGRiLW1hcC1zeW0tbW9kZQAAABEvQ0JDL1BLQ1M1UGFkZGluZwAAABBhbXpuLWRkYi1lbnYta2V5AAABYlZnejZZeFFlNEFBQTNEVzRZZUN5K1Z1OWJPWGs2NzNYbVREV1VRcnZZb00xRTUwTm1KRkNQNlhrWktnMDVNRmFKODRicVBkOHZwelQNCnlxS2pKOWdOQnJ6Sk02MVhvZitPeGErRm02MkIrSzRlVHlOa0U2aFV1Z2U2Q2pqa1pkaW54bHBIZlVBbVJXTXhxcW9JanluR3FWTUsNCm5qS0RYRWkzWHJFSDY3VkhIQnZrcFFVbGg5QVJLNlg1bXFFTHFRb2twamw0b1Z4d1RqakZ6L0c1b2VVSnFkR0R6eXdTSW12NjNESGkNCmhZeWRkSlEvQ1d4VUsxVG5UcVByWnVKMkNneVhQb1pkcEVrMHV5TllGb3dMWm9iNi9kb2VTWjJBdmdHaXBhQS9yZGFlbXZxdVdBbDMNClAxOHRZQ2FOaVhieHM3enRRMExSanp1U3R3Ung0OXRuL09vQUlnPT0NCg=="));
        item.put("stringValue", b642Av("AHMAAAAMSGVsbG8gd29ybGQh"));
        item.put("rangeKey", b642Av("AG4AAAACMTA="));
        item.put(
                "stringSet",
                b642Av("AFMAAAAEAAAAAT8AAAAFQ3J1ZWwAAAAHR29vZGJ5ZQAAAAVXb3JsZA=="));
        item.put("byteArrayValue", b642Av("AGIAAAAGAAECAwQF"));
        item.put("intValue", b642Av("AG4AAAADMTIz"));
        item.put("version", b642Av("AG4AAAABMQ=="));
        ddb.putItem(new PutItemRequest("TableName", item));
        item.clear();

        item.put(
                "*amzn-ddb-map-sig*",
                b642Av("AGIAAAEASNpX+4QUwYC+yMsNiQQcYTXiYWWqnkR02KLn1VRH0YLx1wEuFJiOhhqD4a4AhiorExenoP2HHkZdZMJpGGGU9NbupQIr2SeKvV/dkEXrCADvVaaB5O6xIhsN638f9ibknZLEhUt+XAgGDzhPedKwPBr4ZC0UnQCasedHqb9CGXYMCB8P8URbllcJRayM5mf/bv4vfBW7t9uUTd2p6wsiDNG542pw9unP5+/74mZewfgbbp6bp+8KECVLjwTny24LHdSS7XGRb1uJcZsapnhDDamjctjc1jsaaWk2WWUf2YSp/mGNWgk9+m/St/cRwwVr9wjcGpcMld7QDHEEJQmNxg=="));
        item.put("hashKey", b642Av("AHMAAAADQmFy"));
        item.put(
                "*amzn-ddb-map-desc*",
                b642Av("AGIAAAHzAAAAAAAAABdhbXpuLWRkYi1tYXAtc2lnbmluZ0FsZwAAAA1TSEEyNTZ3aXRoUlNBAAAAEGFtem4tZGRiLWVudi1hbGcAAAADQUVTAAAAFWFtem4tZGRiLW1hcC1zeW0tbW9kZQAAABEvQ0JDL1BLQ1M1UGFkZGluZwAAABBhbXpuLWRkYi1lbnYta2V5AAABYnJQOXA1YnN4eitlbW41dHdWY2dCSHZ0MHJBVW9xa2tzaktTeHJYdTZZTElsSkR3dWJ0MzdrbG90M2IxZGJvRU9mZVFBQkRtcHJFb28NCnVnbTk5Q2paQTBJN0ZRNzJIMElzTEkySUZwV3JzZzRHUTJOM0x4S084Zk5TYW41SGRIWUkwUVlIMjcvMExaQWprbGltckpVeGh2ZUoNCjJYYlFidzhlNWRWTmdLdG1sNkxsTEVWOGlXSG13Z0gwQmtoYzJBUFpIMzlLMHUzTzNBNjd2Yk9pTGlsUWxRaVBJRGhGdlRsWlhtSlgNCmtYYjUyU2R1UXhIMjJubWhFOUc0U0pRMG5BYVhOWkh6S2NZZFJSalBNZmV0VzExZlR2LzhucHRKeGs5YXpQOGl6YnhZR1R5cEh2K2gNCjd6T1NZc2hDUzdWZ0l0MGtsUmJtcDFFV0RtdW5vT2xNZStZaXRRPT0NCg=="));
        ddb.putItem(new PutItemRequest("HashKeyOnly", item));
        item.clear();

        item.put(
                "*amzn-ddb-map-sig*",
                b642Av("AGIAAAEAV0k/mB2e8DSl4lIriyqbYBQbWZDKbiwcfc4ZQB2R3PA+S+hnjiYgwr4zgOXKNk2Dq72M1aIEXzbrej8jVoCSTSiC8pBXxekTqSnUsIYy7ilo8uvoSAN4a8zyfLXxvFPn+ZMwTs48uz7fVe+4MTTIkdd9+sJDTx/ZPEf88mAg3yiQ27cnnqG1N909cvljgjO1ADCcNqfvIMAys3xW5ML4GzdF/G/c/MlRRBMy1rq8HcRC0E09L9BAChfSV3OAwYyns90X5QuTcmpgr5PnY4NFm5WBWYhLwA/nyZDb+Y8e/XAd45i5gLpEpBBxFUiU3X949byFTr/naYFoatBoiWuyKw=="));
        item.put("hashKey", b642Av("AHMAAAADQmF6"));
        item.put(
                "*amzn-ddb-map-desc*",
                b642Av("AGIAAAHzAAAAAAAAABdhbXpuLWRkYi1tYXAtc2lnbmluZ0FsZwAAAA1TSEEyNTZ3aXRoUlNBAAAAEGFtem4tZGRiLWVudi1hbGcAAAADQUVTAAAAFWFtem4tZGRiLW1hcC1zeW0tbW9kZQAAABEvQ0JDL1BLQ1M1UGFkZGluZwAAABBhbXpuLWRkYi1lbnYta2V5AAABYkhQZ3dZSWZzcjlhaVJ6bUIwdVg3WWxkbklUeVRkU3lHTnJIdHVqbytmd1RVUjJabFY3RmxpbjdPS0k3SzNaNE55bFM3RWY1cXk2ZHgNCjRhNkpOT0NCbzIwTTBjbnhEbWFsSG5iZ2p1aUs2ZUhvUzhqbFVvMFl3RDhFcnM1NFFaWExFZVNCQWxucDNUYk55dTlRNkNkTExoRXcNCmtxNkJ0akZNeGtmRk9SaUk3TmdwL21mVmVMSHhqajNleXFCbkpJSmM5RXZVSTVVWlZRK0wvRnAwa1pKdDFuMHdVMFU1UVNqVUVBeGgNCnNQUm5PWHpiZXhGSWdHc05jVE9wdy8vbGoySkZoWGJyWXowNFVqQkpLUEJibTErbllicmZPWi9yU0w2bDRCR3VUTUkwU0pta3ZxbmUNCjkyRmhpUlhJNjJZN0xIZWRzbFAwVnBQMWxXSEhaM1dkbTlVR2hRPT0NCg=="));
        ddb.putItem(new PutItemRequest("HashKeyOnly", item));
        item.clear();

        item.put(
                "*amzn-ddb-map-sig*",
                b642Av("AGIAAAEAQZii10yqicfBPRRi31KpeTnpe5Dp1oSJAqB7L3uyTWUXz+sXeTqsEFqaIebiTtTCixgK3ZCs9mlM4X1V2iEgFWYuCs8mNoO8oY30vXw17E9EpW79kMn8Tuqr6XQqt+lMorFxKjiYcIkhVbNF6greXbSZ1HQdUGIPLQkACQfzX5I6YWjOCcGm60hXb2dp2uZy9kFceKCTIb0OtryI+7bVXX5YH4Ks9IOKNULWNGbjXEr3J2QdkeLcWZgZQVHtaikXiOlaz+WWyU4h9LaL5DxrojDCu68GXDmOzHYUvHbGCfk3y3hhfkwt9vwucEnA+Y3uDGH3vxUerA8iQ6qUH3m8wg=="));
        item.put("hashKey", b642Av("AHMAAAADRm9v"));
        item.put(
                "*amzn-ddb-map-desc*",
                b642Av("AGIAAAHzAAAAAAAAABdhbXpuLWRkYi1tYXAtc2lnbmluZ0FsZwAAAA1TSEEyNTZ3aXRoUlNBAAAAEGFtem4tZGRiLWVudi1hbGcAAAADQUVTAAAAFWFtem4tZGRiLW1hcC1zeW0tbW9kZQAAABEvQ0JDL1BLQ1M1UGFkZGluZwAAABBhbXpuLWRkYi1lbnYta2V5AAABYmI1L0Y2NE5MRlk5eTdVZ05EeUxiYTEwTnpBck1hV2dIZ0hjNndGZncvK0RESVppRUUyRTZSY3NvYnM0U3F3QVROc0JlSHptZjQ4UWQNCjBIWXdyYlVsc3ZOWnl6WHZOMkNqdFVqa1dDdHJOTTJQRlRuVWZHUldPaFU5WDdaR1BPM3FHdzZ1cTVxc1d5eGU5SVhRZTUvbkUvNlUNCnZ1eHlZUG8yR1dwM3BxOS9GSEpIMG1oTCtIL3ROZzBIazRtQi9MV1BxZGphc0F3Zk5ldzQ1Wjh2T3V1aDFGc3hZaExFMmR6Y2VpcVUNCnI0M0dMZGNPVTlsWnpxajF0eW1HTjBubUY0cTBYeVBnVU5pdkJ6anlla1hRTEJBc1RYY0lqNVRrc1lKNHRPR0ZtN3pHdVlVanUrZ04NCm90SGRROThuaGlLMzhnbHFkdDRoOW4zc2FxdGVhMDQwcFA1SVFnPT0NCg=="));
        ddb.putItem(new PutItemRequest("HashKeyOnly", item));
        item.clear();
    }

    private void insertV0FixedWrappingTransformSymData(AmazonDynamoDB ddb) {
        Map<String, AttributeValue> item = new HashMap<String, AttributeValue>();

        item.put("*amzn-ddb-map-sig*", b642Av("AGIAAAAgiZXCp3s7VEMYdf01YEWqMlXOBHv3+e8gKbECrPUW47I="));
        item.put("hashKey", b642Av("AHMAAAADQmFy"));
        item.put("*amzn-ddb-map-desc*", b642Av("AGIAAAAyAAAAAAAAABVhbXpuLWRkYi1tYXAtc3ltLW1vZGUAAAARL0NCQy9QS0NTNVBhZGRpbmc="));
        ddb.putItem(new PutItemRequest("HashKeyOnly", item));
        item.clear();

        item.put("*amzn-ddb-map-sig*", b642Av("AGIAAAAgzh74eH/yJQFzkm5mq52iFAlSDpXAFe3ZP2nv7X/xY1w="));
        item.put("hashKey", b642Av("AHMAAAADQmF6"));
        item.put("*amzn-ddb-map-desc*", b642Av("AGIAAAAyAAAAAAAAABVhbXpuLWRkYi1tYXAtc3ltLW1vZGUAAAARL0NCQy9QS0NTNVBhZGRpbmc="));
        ddb.putItem(new PutItemRequest("HashKeyOnly", item));
        item.clear();

        item.put("*amzn-ddb-map-sig*", b642Av("AGIAAAAgHR5P6kozMSqqs+rnDMaCiymH8++OwEVzx2Y13ZMp5P8="));
        item.put("hashKey", b642Av("AHMAAAADRm9v"));
        item.put("*amzn-ddb-map-desc*", b642Av("AGIAAAAyAAAAAAAAABVhbXpuLWRkYi1tYXAtc3ltLW1vZGUAAAARL0NCQy9QS0NTNVBhZGRpbmc="));
        ddb.putItem(new PutItemRequest("HashKeyOnly", item));
        item.clear();

        item.put("*amzn-ddb-map-sig*", b642Av("AGIAAAAglBLoUXuc8TgsJJlItgBh6PJ1YVk52nvQE9aErEB8jK8="));
        item.put("hashKey", b642Av("AG4AAAABMA=="));
        item.put("*amzn-ddb-map-desc*", b642Av("AGIAAAAyAAAAAAAAABVhbXpuLWRkYi1tYXAtc3ltLW1vZGUAAAARL0NCQy9QS0NTNVBhZGRpbmc="));
        item.put("rangeKey", b642Av("AG4AAAABMQ=="));
        ddb.putItem(new PutItemRequest("TableName", item));
        item.clear();

        item.put("*amzn-ddb-map-sig*", b642Av("AGIAAAAgcjd91WBBFWPnrJxIJ2p2hnXFVCemgYw0HqRWcnoQcq4="));
        item.put("hashKey", b642Av("AG4AAAABMA=="));
        item.put("*amzn-ddb-map-desc*", b642Av("AGIAAAAyAAAAAAAAABVhbXpuLWRkYi1tYXAtc3ltLW1vZGUAAAARL0NCQy9QS0NTNVBhZGRpbmc="));
        item.put("rangeKey", b642Av("AG4AAAABMg=="));
        ddb.putItem(new PutItemRequest("TableName", item));
        item.clear();

        item.put("*amzn-ddb-map-sig*", b642Av("AGIAAAAguXZKvYmUgZEOunUJctXpkvqhrgUoK1eLi8JpvlRozTI="));
        item.put("hashKey", b642Av("AG4AAAABMA=="));
        item.put("*amzn-ddb-map-desc*", b642Av("AGIAAAAyAAAAAAAAABVhbXpuLWRkYi1tYXAtc3ltLW1vZGUAAAARL0NCQy9QS0NTNVBhZGRpbmc="));
        item.put("rangeKey", b642Av("AG4AAAABMw=="));
        ddb.putItem(new PutItemRequest("TableName", item));
        item.clear();

        item.put("*amzn-ddb-map-sig*", b642Av("AGIAAAAgyT2ehLcx/a609Ez6laLkTAqCtp0IYzzKV8Amv8jdQMw="));
        item.put("hashKey", b642Av("AG4AAAABMQ=="));
        item.put("*amzn-ddb-map-desc*", b642Av("AGIAAAAyAAAAAAAAABVhbXpuLWRkYi1tYXAtc3ltLW1vZGUAAAARL0NCQy9QS0NTNVBhZGRpbmc="));
        item.put("rangeKey", b642Av("AG4AAAABMQ=="));
        ddb.putItem(new PutItemRequest("TableName", item));
        item.clear();

        item.put("*amzn-ddb-map-sig*", b642Av("AGIAAAAgYAai32/7MVrGjSzgcVxkFDqU+G9HcmuiNSWZHcnvfjg="));
        item.put("hashKey", b642Av("AG4AAAABMQ=="));
        item.put("*amzn-ddb-map-desc*", b642Av("AGIAAAAyAAAAAAAAABVhbXpuLWRkYi1tYXAtc3ltLW1vZGUAAAARL0NCQy9QS0NTNVBhZGRpbmc="));
        item.put("rangeKey", b642Av("AG4AAAABMg=="));
        ddb.putItem(new PutItemRequest("TableName", item));
        item.clear();

        item.put("*amzn-ddb-map-sig*", b642Av("AGIAAAAg0iwjbBLCdtSosmDTDYzKxu3Q5qda0Ok9q3VbIJczBV0="));
        item.put("hashKey", b642Av("AG4AAAABMQ=="));
        item.put("*amzn-ddb-map-desc*", b642Av("AGIAAAAyAAAAAAAAABVhbXpuLWRkYi1tYXAtc3ltLW1vZGUAAAARL0NCQy9QS0NTNVBhZGRpbmc="));
        item.put("rangeKey", b642Av("AG4AAAABMw=="));
        ddb.putItem(new PutItemRequest("TableName", item));
        item.clear();

        item.put("*amzn-ddb-map-sig*", b642Av("AGIAAAAgGl1jMNLZl/B70Hz2B4K4K46kir+hE6AeX8azZfFi8GA="));
        item.put("hashKey", b642Av("AG4AAAABNQ=="));
        item.put("*amzn-ddb-map-desc*", b642Av("AGIAAAAyAAAAAAAAABVhbXpuLWRkYi1tYXAtc3ltLW1vZGUAAAARL0NCQy9QS0NTNVBhZGRpbmc="));
        item.put("rangeKey", b642Av("AG4AAAABMQ=="));
        ddb.putItem(new PutItemRequest("TableName", item));
        item.clear();

        item.put("*amzn-ddb-map-sig*", b642Av("AGIAAAAgOVOhmBYFqn8JmCr3U53n0gUHm9sOFlCzfslQTndM2d4="));
        item.put("hashKey", b642Av("AG4AAAABNQ=="));
        item.put("*amzn-ddb-map-desc*", b642Av("AGIAAAAyAAAAAAAAABVhbXpuLWRkYi1tYXAtc3ltLW1vZGUAAAARL0NCQy9QS0NTNVBhZGRpbmc="));
        item.put("intSet", b642Av("AGIAAABAOZ4q47AhicK3RzfypoCMvUy3qZNXNejFTSYygP00tL8ox0Zcr6xxxyAHNEf+L/gXv/D2/0fZ1ZXRkUx6I4Q/ag=="));
        item.put("stringValue", b642Av("AGIAAAAwWr8LK3dNif8LCWIEVTk4LsShW/T0/KZqxRFOADzHbI0ou1IFHF+Oy3BwqIP+/zK3"));
        item.put("stringSet", b642Av("AGIAAABAWyqt6ciL7p3eIoT5dnONVBoFLK6nUxnIcC6NylJfdrUWh7/ckBnGMl7c4CCq1ifPD601xrh4+TO99kMSHSaLNw=="));
        item.put("rangeKey", b642Av("AG4AAAABNw=="));
        item.put("byteArrayValue", b642Av("AGIAAAAgj47NBhEawqzHQb6prTGB6RvYyDuh+A4TIrTSwgZoxDA="));
        item.put("intValue", b642Av("AGIAAAAgrwlX4rD1gcqVpnTT4DfX79JPLAtOsw2CYssZ4VS7fnA="));
        item.put("version", b642Av("AG4AAAABMQ=="));
        ddb.putItem(new PutItemRequest("TableName", item));
        item.clear();

        item.put("*amzn-ddb-map-sig*", b642Av("AGIAAAAg66Vz0G8nOQzlvIpImXSkl+nmCpTYeRy8mAF4qgGgMw0="));
        item.put("hashKey", b642Av("AG4AAAABNg=="));
        item.put("*amzn-ddb-map-desc*", b642Av("AGIAAAAyAAAAAAAAABVhbXpuLWRkYi1tYXAtc3ltLW1vZGUAAAARL0NCQy9QS0NTNVBhZGRpbmc="));
        item.put("rangeKey", b642Av("AG4AAAABMg=="));
        ddb.putItem(new PutItemRequest("TableName", item));
        item.clear();

        item.put("*amzn-ddb-map-sig*", b642Av("AGIAAAAgxZvHJ377MCQ4hf1BZJGRgTF+l7YiaydAkILG+7CaQ8M="));
        item.put("hashKey", b642Av("AG4AAAABNg=="));
        item.put("*amzn-ddb-map-desc*", b642Av("AGIAAAAyAAAAAAAAABVhbXpuLWRkYi1tYXAtc3ltLW1vZGUAAAARL0NCQy9QS0NTNVBhZGRpbmc="));
        item.put("intSet", b642Av("AGIAAABAoptMhPYvzeL68/ubOiJu32JBETi7ss0o9nqCSDAN22RaR17CGXge0r6OgJlfWfVFBhUebM/uN42OJpyB3VvuwQ=="));
        item.put("stringValue", b642Av("AHMAAAAMSGVsbG8gd29ybGQh"));
        item.put("stringSet", b642Av("AGIAAABAp3shcn0B9/lVCp9UjP2mRcARZQ8PQC4hR5L0fAsC154j+2kUPu6iRhazVKxkJ8Fr25jtc61X2M9Q32kPwyRmwg=="));
        item.put("rangeKey", b642Av("AG4AAAABOA=="));
        item.put("byteArrayValue", b642Av("AGIAAAAgE1p3OH249idr68bawV56P5lo+nvBvJwbqVPTHMM40/c="));
        item.put("intValue", b642Av("AG4AAAADMTIz"));
        item.put("version", b642Av("AG4AAAABMQ=="));
        ddb.putItem(new PutItemRequest("TableName", item));
        item.clear();

        item.put("*amzn-ddb-map-sig*", b642Av("AGIAAAAgcSTe0npOBBtsxSN4F9mLF2WTyCN1+1owsVoGkYumiZQ="));
        item.put("hashKey", b642Av("AG4AAAABNw=="));
        item.put("*amzn-ddb-map-desc*", b642Av("AGIAAAAyAAAAAAAAABVhbXpuLWRkYi1tYXAtc3ltLW1vZGUAAAARL0NCQy9QS0NTNVBhZGRpbmc="));
        item.put("rangeKey", b642Av("AG4AAAABMw=="));
        ddb.putItem(new PutItemRequest("TableName", item));
        item.clear();

        item.put("hashKey", b642Av("AG4AAAABNw=="));
        item.put("intSet", b642Av("AE4AAAAFAAAAATAAAAABMQAAAAIxMAAAAAIxNQAAAAMyMDA="));
        item.put("stringValue", b642Av("AHMAAAAMSGVsbG8gd29ybGQh"));
        item.put("rangeKey", b642Av("AG4AAAABOQ=="));
        item.put("stringSet", b642Av("AFMAAAAEAAAAAT8AAAAFQ3J1ZWwAAAAHR29vZGJ5ZQAAAAVXb3JsZA=="));
        item.put("byteArrayValue", b642Av("AGIAAAAGAAECAwQF"));
        item.put("intValue", b642Av("AG4AAAADMTIz"));
        item.put("version", b642Av("AG4AAAABMQ=="));
        ddb.putItem(new PutItemRequest("TableName", item));
        item.clear();

        item.put("*amzn-ddb-map-sig*", b642Av("AGIAAAAgiWWvGpcrzkUu241+NNtykoiWoeaSR3QHQMhHTmf0XAU="));
        item.put("hashKey", b642Av("AG4AAAABOA=="));
        item.put("*amzn-ddb-map-desc*", b642Av("AGIAAAAyAAAAAAAAABVhbXpuLWRkYi1tYXAtc3ltLW1vZGUAAAARL0NCQy9QS0NTNVBhZGRpbmc="));
        item.put("intSet", b642Av("AE4AAAAFAAAAATAAAAABMQAAAAIxMAAAAAIxNQAAAAMyMDA="));
        item.put("stringValue", b642Av("AHMAAAAMSGVsbG8gd29ybGQh"));
        item.put("stringSet", b642Av("AFMAAAAEAAAAAT8AAAAFQ3J1ZWwAAAAHR29vZGJ5ZQAAAAVXb3JsZA=="));
        item.put("rangeKey", b642Av("AG4AAAACMTA="));
        item.put("byteArrayValue", b642Av("AGIAAAAGAAECAwQF"));
        item.put("intValue", b642Av("AG4AAAADMTIz"));
        item.put("version", b642Av("AG4AAAABMQ=="));
        ddb.putItem(new PutItemRequest("TableName", item));
        item.clear();
    }

    private void insertV0FixedWrappingTransformAsymData(AmazonDynamoDB ddb) {
        Map<String, AttributeValue> item = new HashMap<String, AttributeValue>();

        item.put("*amzn-ddb-map-sig*", b642Av("AGIAAAEASNpX+4QUwYC+yMsNiQQcYTXiYWWqnkR02KLn1VRH0YLx1wEuFJiOhhqD4a4AhiorExenoP2HHkZdZMJpGGGU9NbupQIr2SeKvV/dkEXrCADvVaaB5O6xIhsN638f9ibknZLEhUt+XAgGDzhPedKwPBr4ZC0UnQCasedHqb9CGXYMCB8P8URbllcJRayM5mf/bv4vfBW7t9uUTd2p6wsiDNG542pw9unP5+/74mZewfgbbp6bp+8KECVLjwTny24LHdSS7XGRb1uJcZsapnhDDamjctjc1jsaaWk2WWUf2YSp/mGNWgk9+m/St/cRwwVr9wjcGpcMld7QDHEEJQmNxg=="));
        item.put("hashKey", b642Av("AHMAAAADQmFy"));
        item.put("*amzn-ddb-map-desc*", b642Av("AGIAAAInAAAAAAAAABdhbXpuLWRkYi1tYXAtc2lnbmluZ0FsZwAAAA1TSEEyNTZ3aXRoUlNBAAAAEGFtem4tZGRiLWVudi1hbGcAAAADQUVTAAAAFWFtem4tZGRiLW1hcC1zeW0tbW9kZQAAABEvQ0JDL1BLQ1M1UGFkZGluZwAAABBhbXpuLWRkYi1lbnYta2V5AAABWHFremNPOXl3MlpwUlh5U1pRQ2Jra1BxKzkyakJIZ2hpUmh2Q3hQTS8yNGVjdW83SFdvL2FDRHl1NTZ6eFJ5UkhiVkNnTUw5V2tua1dBTWhOL1UxMFJjOUhKQzlmd0pYM0h0cUVxVXl0T3NqZjRzUlhRWElKZmNoTjRKNFlYNHROQ3pZT3EzWE1BcUxCUng2L3ZkbFp3QUVCSURLVnJQWkZVcHEyZlVVYkNNeCtxSWV3NGJwWVRsVmhteC93MlZ1d2JldHRTT3huckxiOGZINCs4VGpGZ29MMlgrSnk5MERUV3EwNTdoVStDbUx3RjVxazJKaVRuenpSOFY4S1lVOUJTNXJydlBDcmd2N1g1S2QxYlc3akd4dlE5dk05cFI1TysrQ3dQUCtKVE9YbGNFMXluRXpRSFd3d3EvSG9RalJBaXRjaDFINDd0WUJPU3pPSHNYUUZGUT09AAAAEWFtem4tZGRiLXdyYXAtYWxnAAAAJVJTQS9FQ0IvT0FFUFdpdGhTSEEtMjU2QW5kTUdGMVBhZGRpbmc="));
        ddb.putItem(new PutItemRequest("HashKeyOnly", item));
        item.clear();

        item.put("*amzn-ddb-map-sig*", b642Av("AGIAAAEAV0k/mB2e8DSl4lIriyqbYBQbWZDKbiwcfc4ZQB2R3PA+S+hnjiYgwr4zgOXKNk2Dq72M1aIEXzbrej8jVoCSTSiC8pBXxekTqSnUsIYy7ilo8uvoSAN4a8zyfLXxvFPn+ZMwTs48uz7fVe+4MTTIkdd9+sJDTx/ZPEf88mAg3yiQ27cnnqG1N909cvljgjO1ADCcNqfvIMAys3xW5ML4GzdF/G/c/MlRRBMy1rq8HcRC0E09L9BAChfSV3OAwYyns90X5QuTcmpgr5PnY4NFm5WBWYhLwA/nyZDb+Y8e/XAd45i5gLpEpBBxFUiU3X949byFTr/naYFoatBoiWuyKw=="));
        item.put("hashKey", b642Av("AHMAAAADQmF6"));
        item.put("*amzn-ddb-map-desc*", b642Av("AGIAAAInAAAAAAAAABdhbXpuLWRkYi1tYXAtc2lnbmluZ0FsZwAAAA1TSEEyNTZ3aXRoUlNBAAAAEGFtem4tZGRiLWVudi1hbGcAAAADQUVTAAAAFWFtem4tZGRiLW1hcC1zeW0tbW9kZQAAABEvQ0JDL1BLQ1M1UGFkZGluZwAAABBhbXpuLWRkYi1lbnYta2V5AAABWFQ1WlltM0doNGZ3UnBmUE9MMWduSTdaekNSbWtXa1kzZjVqV2h0NGZ4a2QvMnF4NWNxNm5aa1IydFhoL09ZQjVvZVE3VDRBUVZBNE95TUsvVDJ6QUNSallhNlhSdE92Y05EdnVRalVGUHVBbThKRUlOZWd0cER4RjZreklYZG8zanhQenZscWNFakZxdnpBdDRBWGxCa2hZOFZGeFBCc2lRV2owUTdwYUJxak5DWGNjZ2lLdG83U0ZTaklCNmZNRFFtWkNaNUpFRHVLcXkrY1h4UytyOGJLODVaMTBwMlB0YzZUVVZZdEExVTdXUmxwOThIZExUL1lJZmhoQlVDT2hLN3ZXN3c3WWp0T3g0UTRUT2dnbndBQndxclEvUXlrZXZCaG9SVHRoQ2NkR1JqUVdrTXhSaW0yQkNaeWgwS0NtZStTUFhKcXAvbTZybVlxbEFxUUtyUT09AAAAEWFtem4tZGRiLXdyYXAtYWxnAAAAJVJTQS9FQ0IvT0FFUFdpdGhTSEEtMjU2QW5kTUdGMVBhZGRpbmc="));
        ddb.putItem(new PutItemRequest("HashKeyOnly", item));
        item.clear();

        item.put("*amzn-ddb-map-sig*", b642Av("AGIAAAEAQZii10yqicfBPRRi31KpeTnpe5Dp1oSJAqB7L3uyTWUXz+sXeTqsEFqaIebiTtTCixgK3ZCs9mlM4X1V2iEgFWYuCs8mNoO8oY30vXw17E9EpW79kMn8Tuqr6XQqt+lMorFxKjiYcIkhVbNF6greXbSZ1HQdUGIPLQkACQfzX5I6YWjOCcGm60hXb2dp2uZy9kFceKCTIb0OtryI+7bVXX5YH4Ks9IOKNULWNGbjXEr3J2QdkeLcWZgZQVHtaikXiOlaz+WWyU4h9LaL5DxrojDCu68GXDmOzHYUvHbGCfk3y3hhfkwt9vwucEnA+Y3uDGH3vxUerA8iQ6qUH3m8wg=="));
        item.put("hashKey", b642Av("AHMAAAADRm9v"));
        item.put("*amzn-ddb-map-desc*", b642Av("AGIAAAInAAAAAAAAABdhbXpuLWRkYi1tYXAtc2lnbmluZ0FsZwAAAA1TSEEyNTZ3aXRoUlNBAAAAEGFtem4tZGRiLWVudi1hbGcAAAADQUVTAAAAFWFtem4tZGRiLW1hcC1zeW0tbW9kZQAAABEvQ0JDL1BLQ1M1UGFkZGluZwAAABBhbXpuLWRkYi1lbnYta2V5AAABWHJFbldWQmRWVHdpOERuOG9qTHQ5R20zV3dCTm9nYWZmbFBXdmRCODYzL1Buemtsc3N1QzVlaThUVGlOY09NVzlqZGZvTEtLTWRrVm5OQ3BpaDc5QWRTU0ZpalVERXNnODNZdHFlS1JYRzdsd1B5KytnYTBkOXhFWmMwZHlPN0FSS1ozekcwU25NcVBhTEFIdURaYUQvSzVIVDRPeDZpaGpmS21PQ1Y1QytFQlNRaFVRUTk0QjVOeG1EOUZObEl2MHp6QXpXUVo0R0htTTI4ZS9tMWJGZ1hITExLT0s3cVFhZjM1TWNqNHFoVUNJVzV0TjVFSW9hK0tTYWxtZkMvRE5ub29oU0JWejN4cDdpbU9wUkMwdUZXdW1HaHRpR2krYVl0czJwOUdodUpobHFvQi9RSk93TDVDKzNNelZRaHJWUG5aMWRYemhtTHBGblUrTTYrRDl5QT09AAAAEWFtem4tZGRiLXdyYXAtYWxnAAAAJVJTQS9FQ0IvT0FFUFdpdGhTSEEtMjU2QW5kTUdGMVBhZGRpbmc="));
        ddb.putItem(new PutItemRequest("HashKeyOnly", item));
        item.clear();

        item.put("*amzn-ddb-map-sig*", b642Av("AGIAAAEAVRRX8l/eqIeMo7TvQbHI+0Zfh6tbwT5rFJ2zTLYoloudkb8WcBjcHuHEGUhFia6lSKOXwU1cEi/dT4YbQUXf2vzVTxS7jDstYHwHxscVPYNKp7FKzrG/Rym2lF1D78cTn46Zu2/XPw/JgTUhL0Ar7nmmDjUONzzd41QZGr45PFtgBZzGSHyyIpWU2+TRA87quKL71YnrzfbfWoIutJLQ8lAuGlx/gm++09c8PCL60CwUGl6moaVzSYpu/zR+1lxFZ67sWnNrxlsezsQcWUbPJKgeaHfeKDxSevaALTS9dCAjSlE0Sv7XbsdjxW2huNPcPTQCOcqUtetDJ1W2GLa1mg=="));
        item.put("hashKey", b642Av("AG4AAAABMA=="));
        item.put("*amzn-ddb-map-desc*", b642Av("AGIAAAInAAAAAAAAABdhbXpuLWRkYi1tYXAtc2lnbmluZ0FsZwAAAA1TSEEyNTZ3aXRoUlNBAAAAEGFtem4tZGRiLWVudi1hbGcAAAADQUVTAAAAFWFtem4tZGRiLW1hcC1zeW0tbW9kZQAAABEvQ0JDL1BLQ1M1UGFkZGluZwAAABBhbXpuLWRkYi1lbnYta2V5AAABWENNRDA0MG0reDd6am94YkZNb2FzRDJ5cU1MRGVzWnpwZlRGMXNNcDVHUDM0NXljTWlIbnhONDRLUEJQUlE5clh5bjE0T01wVko2bkNBVFMvMUdnRVRLdTYrQmdmeEtFZ3NYZ29wRWtVOE52QnJ5S1creHlyeFN1bHFvUG1JR2pnM0hpMEd2YnRvcnRkeGt0NTVEbXVyZkYyTjVKbnZtUmIvZmRscGRkdEJsTVNycTR2UFZtS0UrbTl2b0hwNVE3VzdoZ2RDODVxZGE5MVBkd1hsb1RRZU4xS0NhWmVlTUtnMlF2a1BSa2hWbHNZOFJwekVrZEFSRWxDLzBwT3VTQS82ZURhbU1hNTEzK3VqKzNlRmZ4ZzNPS2MzL1VSSHpGY2NGb1p2VjZJcmtkODN5TWwxVkpIaGVKbGxTU01UeGFwWitOSXp1THRJNGhUeHh6bElEYk1pUT09AAAAEWFtem4tZGRiLXdyYXAtYWxnAAAAJVJTQS9FQ0IvT0FFUFdpdGhTSEEtMjU2QW5kTUdGMVBhZGRpbmc="));
        item.put("rangeKey", b642Av("AG4AAAABMQ=="));
        ddb.putItem(new PutItemRequest("TableName", item));
        item.clear();

        item.put("*amzn-ddb-map-sig*", b642Av("AGIAAAEAMG6vTV+uPAaPmZIGR4I4DbUwIUmivEZQ5sqpK83hue0SArv2a9TtlOTIighJa3b+u/LR/0kxm2Jbx5nqrI7oT0eKSjqJYk1S3w2W/JDPzyk4wwwSoOKH4TLq0KxwXE7QEM4aS5hs92ja6jKPIj7nEJKYOOwHdCdu3Qu2SBmY0VWyj+pUohZv5fzDD81nMeCWU7KmtFsXfKAFFHM2ufCWywXRBXKfYTDPYR87+bfNvbw5W/FmDeu9pdpCIbV66yR3pl4d9+FLoDqbS5yQjKzDI+X5Z90FBaW1xaPCKLcp2l9tRq8q8hfvyXZXrJVisu+/igjqpZ3Tszj9XBmmqLFo/A=="));
        item.put("hashKey", b642Av("AG4AAAABMA=="));
        item.put("*amzn-ddb-map-desc*", b642Av("AGIAAAInAAAAAAAAABdhbXpuLWRkYi1tYXAtc2lnbmluZ0FsZwAAAA1TSEEyNTZ3aXRoUlNBAAAAEGFtem4tZGRiLWVudi1hbGcAAAADQUVTAAAAFWFtem4tZGRiLW1hcC1zeW0tbW9kZQAAABEvQ0JDL1BLQ1M1UGFkZGluZwAAABBhbXpuLWRkYi1lbnYta2V5AAABWEhTY2swR0lJQXBPT1hvenpudVlpRjJNOUZQZG1FNUpsejBLTlBsaFJPcHVzaDliNzhseGxBK01QYkMySngveEQ5NnZVTmtqTW5Dc1BkbFZDcHQ5QmV4ZkdGNkYzbC92QWVOeVRMMEFvTkdYRCttMWVCL2tIbm5ZalVyWUJ0U2ZseWxlOHF1UEZZRzVxbkppZm12SGRzRXk3R2VnREZKM3M3NktqaU5RNDZGWW9KTXVUblN5OXlRekhtbm9uUDVrcXliYVB4b0E2TTE1Z0JQYjNiWlNTUHpTYmQ2M2M5cVU4UW1DMWVtY05TWUxYTFYyZGUrUmhaRFM2YnlnNTBuTkQrZXRPUEpnUmNCVjhVd3J0d0RFSGo3SUcvbXdqWWcwM0hxdUxjcUhUcG5BVFVOeVJVMHVYTGtlZmpRRStxSTZiS2xSTHdac1gvYndwOXFLdGJOOW1sQT09AAAAEWFtem4tZGRiLXdyYXAtYWxnAAAAJVJTQS9FQ0IvT0FFUFdpdGhTSEEtMjU2QW5kTUdGMVBhZGRpbmc="));
        item.put("rangeKey", b642Av("AG4AAAABMg=="));
        ddb.putItem(new PutItemRequest("TableName", item));
        item.clear();

        item.put("*amzn-ddb-map-sig*", b642Av("AGIAAAEAed4gAI82hqUpvoUH/glIJXIbasq7CDMbcfm2u/fojO+3FsujnsCRCcIJZIe6ny3ExNC/o272WzUL+Tw1tFnM0VYcS1aAgpdJiTyX4LFPp4uJRlutcxDWCOBpAVh+Ma/oIQDAgxlm1EOcKiWyxhyXm3Bjm8c//rV/YyMkm7NpqK99zCfbgnwI/ezGvEaJe5L3N4eLZBAV9BG7B6if9uvSvCWh3NABr9XNeaXLCHC300ENCk8iUNJJASi1sGQnlTR186Ix8s4DPCfZJbNwWlHrbupgmBq+AZRffbU059QrLfvzdxpaRtHIlDxQwmvk8C7EU2kUuLGyEA8XSdiT5y2fRw=="));
        item.put("hashKey", b642Av("AG4AAAABMA=="));
        item.put("*amzn-ddb-map-desc*", b642Av("AGIAAAInAAAAAAAAABdhbXpuLWRkYi1tYXAtc2lnbmluZ0FsZwAAAA1TSEEyNTZ3aXRoUlNBAAAAEGFtem4tZGRiLWVudi1hbGcAAAADQUVTAAAAFWFtem4tZGRiLW1hcC1zeW0tbW9kZQAAABEvQ0JDL1BLQ1M1UGFkZGluZwAAABBhbXpuLWRkYi1lbnYta2V5AAABWGZLWHJVY0NjZjdSOGpTbERSVEkyOVRDMEFMbXlVQjBCQzE3WmZBLzlQTjNkYldNamhTb2FCNjhzUFU5ZkFCQld4YzliZDZRZFFndkxHM1cwWmgzZzFuWWpVYTVkbklUdU1TU0Rxdm81MENZbkI4QXp5dmU0NmVXNitJYWh5MlZJR3pWMVRkWHA5MnoycXhSUHNMOFlkVmswZ01MTUh3cERadXljZE9RYTAyQllJWVNZSHQ4NlNDSllxWjVoejBrc3hCaTFBTHM2ZzFBTGNiNHMwRU5nbWoyZ09wV2xQeGNXOCtVUVFjWVpHWEFGUDEyWkpzNk9rM0ZoM2tiMlhzR29uWFBweGZtaUpCU0paMjJ6UWNiekJ1S2VHOWxVdG5nSExLb3dqU0t1NTNKR3pjTXl4MHdCQmF2SGI2aFNicVh0YkRKcXRCaHMyRXRzMkdlZzlKZzRzdz09AAAAEWFtem4tZGRiLXdyYXAtYWxnAAAAJVJTQS9FQ0IvT0FFUFdpdGhTSEEtMjU2QW5kTUdGMVBhZGRpbmc="));
        item.put("rangeKey", b642Av("AG4AAAABMw=="));
        ddb.putItem(new PutItemRequest("TableName", item));
        item.clear();

        item.put("*amzn-ddb-map-sig*", b642Av("AGIAAAEAMaO/4MFm20VFjw2ER/jpwi6iR2VBYKp+uwdJH+/CZv1NlwMDp+9t7MHu9DArLIzQlHjUQ905a8FV9LeNHcDD29CNDXz3u0I6u7Rznhoa78N6fO08aDdHn+MtLzoZaKi7dpJ1M2xNzAM/3x2dTkLiCGKuAOnpmk4SSG2vKu1OssM4e9VTwWgdWgUBHyMef38fEoT55XRy67phr4e77kVesV+X/lM+JudGuzxZgbrFsFVgy98DQ2SJF4gpNKkNOeWKFIomT8bEukxECfi0Vyk/m7PSMKgvF5JBBNQYEt7HXRUo1lVmUc7WvBHYU4dVkz2oQZn06F//IAZo+qsmqOM12Q=="));
        item.put("hashKey", b642Av("AG4AAAABMQ=="));
        item.put("*amzn-ddb-map-desc*", b642Av("AGIAAAInAAAAAAAAABdhbXpuLWRkYi1tYXAtc2lnbmluZ0FsZwAAAA1TSEEyNTZ3aXRoUlNBAAAAEGFtem4tZGRiLWVudi1hbGcAAAADQUVTAAAAFWFtem4tZGRiLW1hcC1zeW0tbW9kZQAAABEvQ0JDL1BLQ1M1UGFkZGluZwAAABBhbXpuLWRkYi1lbnYta2V5AAABWGJ2OTlUVTVNbUozRVJ1Und0ODdZNE0wVnptZXdnNXhRUFg3R0FSR2hkYXhDNGZQNFphMUlWOTQ5V3pQcjJvRXJsaVhLTjc2STY2bWJHd0piZ1Q2UzJtdmlFRWYwZXl2bDlKTTNSUmNzbFpsVmpMSzFFcDc2aGthNGpoclhVaURuaUNTZndPYXlYbm9GMDhIMml4S1YxazdPZFBvazRDcms3UHNFZlh3UmN0eGU5SmoyaTZ1Vzk5a3VielY1R215Q0FPRDNweTgzZEJtME4wVG9RMDJaMmlJYUlYb2I3cW5nTlBDZEtDakpyQ21xbE9KTUswOWJsRkFucUhvc3E4K2wyNXIrOVhtSnErajByZjZJQ09MMDlteGpFZkZnOHFYaVAxSGUrWUt6YStIbTU4MWZ4dnY1QUtpUngwaFlDc1p6VkZLODlVN0FJT1NISnlxaVUreTJuZz09AAAAEWFtem4tZGRiLXdyYXAtYWxnAAAAJVJTQS9FQ0IvT0FFUFdpdGhTSEEtMjU2QW5kTUdGMVBhZGRpbmc="));
        item.put("rangeKey", b642Av("AG4AAAABMQ=="));
        ddb.putItem(new PutItemRequest("TableName", item));
        item.clear();

        item.put("*amzn-ddb-map-sig*", b642Av("AGIAAAEAfq5jMK7LBRwa63vh+Unxjxxuj8ugx/l0jqRalmWNql+k/RTz3lxsNCTFh1svGTP4QZTLL/GghdZGmGH2Pb82M45ExGsvZoVzkdQ6Gc/y8NNCMkD98pZyYeWchDazrqC1EnB+IoYbuG5vQF5vCwR2jEfd42bu+YnPMy3ackMEF9fDamQdHsAwfDDFsshmePA0Q4RMOaBUu48YhrDhSYPXH2DAv8lwPqh4lWGOrtalV5MFCvVzFO5ss47XDeI5zjafkwoJQPU5b44cvvLXeq56p0cWn9uFt2XMZ3HBHxDOOOAUkqNKShlaQ3m39SdU58fN50MLrc3G3mUjbttFBBE5AA=="));
        item.put("hashKey", b642Av("AG4AAAABMQ=="));
        item.put("*amzn-ddb-map-desc*", b642Av("AGIAAAInAAAAAAAAABdhbXpuLWRkYi1tYXAtc2lnbmluZ0FsZwAAAA1TSEEyNTZ3aXRoUlNBAAAAEGFtem4tZGRiLWVudi1hbGcAAAADQUVTAAAAFWFtem4tZGRiLW1hcC1zeW0tbW9kZQAAABEvQ0JDL1BLQ1M1UGFkZGluZwAAABBhbXpuLWRkYi1lbnYta2V5AAABWFdpcEVnbm5uTm9adGZKZ1JibktFbWlJZlh1dDluNEorR3N4YTZ3NTZJVkFZQk5Oakg0Q1RXaGZKcXlEZjc3UVlNQTNhNVdQeG5SeDUzTk9JNStraWgxcmlrS3lqaFpXTDh1ZlQxOUwwWTZsd1FjTUFaekRGckVFSS9UZW5EWFJQZUR5UnBXR01NQWZCbnlaMzl0aGUrRXNzYk5aZ1poWndtaVRYNlYyUlVmQ0tuRUFlVk40eXB2NVdzUEJIcnFmdXBtVXNBVjF4MFdVNUVSSnhNNUl4SURhL24zOFlqOEVsa09mY3pYbzlNbTBmOE8xVmJKZGhQbVVmZEYzQkxIcWdMY1o3aDhNWDUwVjdlYm83ZWY2SkdWR293MFVVVGRwUC93K3l6RFUvK1dQQnpwR0wwSmgzaFhQK010M2dxZXBLQXBXOWtGRXBKTzhQOVMrMFN3VEhVZz09AAAAEWFtem4tZGRiLXdyYXAtYWxnAAAAJVJTQS9FQ0IvT0FFUFdpdGhTSEEtMjU2QW5kTUdGMVBhZGRpbmc="));
        item.put("rangeKey", b642Av("AG4AAAABMg=="));
        ddb.putItem(new PutItemRequest("TableName", item));
        item.clear();

        item.put("*amzn-ddb-map-sig*", b642Av("AGIAAAEAraKHapJyc7wtw9Qzbr4c4AbRlLAT8p0rkrN+gm3JFSJwFLHtf6dHBQv9tveVRNo4VMeV+PJDbWDcPDEivK4Vq5N9BAlveRSx+d9Mj/ueK323VUIGynQwdI2PO0J4pncTvFIH/VMauMcCItOlmaOV/pKogUIYLqEGdgqPd5M6TuL0Gxki9i9lzZOg10yJZjTIg33I4L1C04xQVZ7c9gcyQB715y0TwF+0oXs1EG2KtUdF2oS2yqCb67v226gdj5aoFNUzfijy7v3s3cRMVA0fQKwpda+d9Rj5NzkvwBo43oKFFh58tl6FbRa3nN9Jj9cxWGtTSIlVd9RQ+vttzObdIg=="));
        item.put("hashKey", b642Av("AG4AAAABMQ=="));
        item.put("*amzn-ddb-map-desc*", b642Av("AGIAAAInAAAAAAAAABdhbXpuLWRkYi1tYXAtc2lnbmluZ0FsZwAAAA1TSEEyNTZ3aXRoUlNBAAAAEGFtem4tZGRiLWVudi1hbGcAAAADQUVTAAAAFWFtem4tZGRiLW1hcC1zeW0tbW9kZQAAABEvQ0JDL1BLQ1M1UGFkZGluZwAAABBhbXpuLWRkYi1lbnYta2V5AAABWGljaldDWmg5dlNDTXhQZE1mNlVKdkpDME9jMGR5cFUycUJ3ZlZmOG9zRWxjb05ZdkVaeGtPQlFrcnpIVmtZaVI1dHBRelplOUZ6QzFnelZOSUNYSDVuWVNZN29sNTJISlN3azhtbDZaaGw5T0F5bHA1SVhISEkydnhyUFhRa3BsSzJjcDZLQjAxQWltQ3VwZTI4dCtQR3JUOGdka2Q3UG5TMlBTVmMzTnJpUXZVU1Q2Q0VpMnNaSUVnMDA1Ui84MDJUc252eGtGdnNyTVU4SVlhN2NodFEydHdEK1I3QXpzeE9OdnBjU25ud0t2NEtKd3RobjVnNlVNdVJHcXhKZHB4cUxKSGxqQXhNQTZiajFEWEVNNXgrUkF1NWExNEppbmRFSjJ4dUN3Yk1zSWVwR3BXTHFGeFA0SlZuL2F2bmUwcWVURGUxNXlMRnpWcmJPdkNFbEk3dz09AAAAEWFtem4tZGRiLXdyYXAtYWxnAAAAJVJTQS9FQ0IvT0FFUFdpdGhTSEEtMjU2QW5kTUdGMVBhZGRpbmc="));
        item.put("rangeKey", b642Av("AG4AAAABMw=="));
        ddb.putItem(new PutItemRequest("TableName", item));
        item.clear();

        item.put("*amzn-ddb-map-sig*", b642Av("AGIAAAEAMlADNyM2Rd+jSXzd/NgK53qnNIWrjOswmITkLKy6wmuP7tyYZZfdz/yN9rv/AeaDF0SKxQiTkIuWxtibyATiEFLc2DdulIx8Kl2ZydWSgvEI8ZCrKDNjhX8auceL2XZwqUQEWgNIoSRj+TpXZNwxygg0ZyT9d+PP8RT3yM64/9A2nW9WHMWK/ASwGJVHo1dlDzdspvcUCEtkO7U4ey9q25HX7YDx5p+yMxUH360fDuDYnXIdMyOSwPFO6LkcBpkxWSHsgB1jSZ9bVVceXi+mM3sUL+aLkUd/sP9Yl5/mOKASpJezNKcetAdSaC7VSKJ1PMbcEDSmK6XqblnNGF1L/Q=="));
        item.put("hashKey", b642Av("AG4AAAABNQ=="));
        item.put("*amzn-ddb-map-desc*", b642Av("AGIAAAInAAAAAAAAABdhbXpuLWRkYi1tYXAtc2lnbmluZ0FsZwAAAA1TSEEyNTZ3aXRoUlNBAAAAEGFtem4tZGRiLWVudi1hbGcAAAADQUVTAAAAFWFtem4tZGRiLW1hcC1zeW0tbW9kZQAAABEvQ0JDL1BLQ1M1UGFkZGluZwAAABBhbXpuLWRkYi1lbnYta2V5AAABWGRMN05wNXRiTDQ2SEVhcDBlNCtGek5KditIMmo2WkZIdTdHQmZYZUdNTWlUaE1Ibklkb0hrVmQ3WUg1OEVaZVU5dElNVEh2cHVTT1NlV2V4NFVMbUZNYXVHM2o0aEFOZ0ZOOEtKR296STE3dlJQaWhmcmZ1VW1QQlVtVzZwTi8xYVpXejhtQlJBSUVyamRRMFFuWHFxaWoyNGl2QlNwVHB6SVY2MExTYndCeFJMYU9OYVhIVXNtTUF5U1k3NjJJZWtrbWMwWDd5MEJmRDRnQXVZbTdlU013SHdyR2l4QjZJbFJjQVp4dElPSVVoRGhIWWwxa1FWVExoZ1k0Q0N6eW1TbHo3bVlBNHBGVHhYeE5KRGZsYVg0TmE4eFBmVy9yL1hJZkZOdUZuajUxSzhKTHhueHNUM0VKV25FNXN0bktFcldHVEhHMFlhUXN0MmYvZ05QbEhKUT09AAAAEWFtem4tZGRiLXdyYXAtYWxnAAAAJVJTQS9FQ0IvT0FFUFdpdGhTSEEtMjU2QW5kTUdGMVBhZGRpbmc="));
        item.put("rangeKey", b642Av("AG4AAAABMQ=="));
        ddb.putItem(new PutItemRequest("TableName", item));
        item.clear();

        item.put("*amzn-ddb-map-sig*", b642Av("AGIAAAEAcXwsjmUgMBWevJTnvjoJHkcpr4Lq9EynnWDVpHTuVT+981Dwfz9Tb77Ct9PrlpH2tmLAPa7Men6fweM96FHixKZprq4fpDtdS8/uYpwR/R1A3YJ2PV/7Z5tpnbcsK7vzWv5FFfu7ExiDhiyo3BO0tUfzmgIj+n6AC4t+Av1H+ezftU5RFvrZRLyXqznb4BgGMFw2hrp492AmgRmkyn7tH0gSH2ov5511xXTLDxb+4FN1pcFMXunegJ/mrTZbAEpA5cwSmFrAG5HF9+1HMaW4xkKngG/RDM1uAqW39cFwullfdwQrfGdWcjP8S3gwZjRBYBuVmmT4I9+iReWtKyffwQ=="));
        item.put("hashKey", b642Av("AG4AAAABNQ=="));
        item.put("*amzn-ddb-map-desc*", b642Av("AGIAAAInAAAAAAAAABdhbXpuLWRkYi1tYXAtc2lnbmluZ0FsZwAAAA1TSEEyNTZ3aXRoUlNBAAAAEGFtem4tZGRiLWVudi1hbGcAAAADQUVTAAAAFWFtem4tZGRiLW1hcC1zeW0tbW9kZQAAABEvQ0JDL1BLQ1M1UGFkZGluZwAAABBhbXpuLWRkYi1lbnYta2V5AAABWFNMbk1xMlcyM1lMbFZnUG16dUIwSGcySGlrRTE0VUowZlU4cG45SlVVSG0yUmZkNFR4aTd1MkpkWmRUcXB6NVNvOG9XNHBPQkw0ZlJKN09EUXpLN1U4dWZzTDJaa2gwL0U4STZoSVVHa3dlYnhXdll4eEtuUWYzRzd6ZG1BTWVVU0JDWGx5amgyTzFrMXVSZVAvREkzdDBhcThkVFpZVDhGZ1UvaWpPb0tNRzlTdk9SQjJJK0NlL2RPb21KTEhLSTloT2RvSHNsZ3BEUGlFR2JRemtrR2Z5SmJVQWdMN01UQnNnM1NreUFiQWNHa2NKM1lVTk5STDJaczBYdnR0cXdYWWpqRGZjUFFURlY2UXJHNWEzK3l5TzJKUkQ4UlZGcStTcUQrVjBHdGNHZlB3OE5aV1RyNnlnNHh4ejVMSnJuWStZbmo3ZUQ2SmtXMnp1SjZlSUp6Zz09AAAAEWFtem4tZGRiLXdyYXAtYWxnAAAAJVJTQS9FQ0IvT0FFUFdpdGhTSEEtMjU2QW5kTUdGMVBhZGRpbmc="));
        item.put("intSet", b642Av("AGIAAABA8ZtcMSFyLVWShX6ppvvQSieBh7o22ZgvG2W9YnfvAl0Skl8MSs5ARJBSFjfwu1ZUkkAu4TkSVDzYHQ6OyVqY3Q=="));
        item.put("stringValue", b642Av("AGIAAAAwOai1ObEsra4j02oNBT/sjPPbs90yHVhv1sj/+JWeLADZb0BcIgjI/YZpJf16khFf"));
        item.put("stringSet", b642Av("AGIAAABAvzb/AuXZQzfsY6g9eCX1bfnIaNrP4AmLmsEsG9c2vhV0DsRUBuJ7A5eRJCUkS6M3V41+kL1wl0kPQ2KE2ldVMg=="));
        item.put("rangeKey", b642Av("AG4AAAABNw=="));
        item.put("byteArrayValue", b642Av("AGIAAAAgKAywNi4WcQfbA327kGuM/gvIezcA4/jBlnZDXhl8M+U="));
        item.put("intValue", b642Av("AGIAAAAgZmWF+am2vPEV2IkuCb/6ULBiGYSvjR6OwCcQxfQ4uS8="));
        item.put("version", b642Av("AG4AAAABMQ=="));
        ddb.putItem(new PutItemRequest("TableName", item));
        item.clear();

        item.put("*amzn-ddb-map-sig*", b642Av("AGIAAAEAjKVKU8uHbhAg8vlU8WqK3qIss6XKPJQXATVwFlkqw5N7RMj0yjQWQ5pJC81sdkXp3NmIgF9Wnavzl5TEVB6R4v/cwxT85ih/kMN7NDOXU5OEkQUlzCRCZ3U6wVvWgFbbI68r42LNPav+uuWBB2/cp9Uu/4VbsOQC7IjEdWIPkir+5BP7HBFg78cs9YgpkDuw2J8+4KLj4z5CsSW6dPjhmbPolKmhn8DinezJ6bHpRFmP0ry75HxMUTu2wInwHD0mCpK1TXWJ3t8V1+UJkNHHpD6j78UhNH9Ky2h9pgj+7Gml0pnZ9t0skUCXNcBLf0Pj3RsqvQuYrU6f2tV8DDxm8g=="));
        item.put("hashKey", b642Av("AG4AAAABNg=="));
        item.put("*amzn-ddb-map-desc*", b642Av("AGIAAAInAAAAAAAAABdhbXpuLWRkYi1tYXAtc2lnbmluZ0FsZwAAAA1TSEEyNTZ3aXRoUlNBAAAAEGFtem4tZGRiLWVudi1hbGcAAAADQUVTAAAAFWFtem4tZGRiLW1hcC1zeW0tbW9kZQAAABEvQ0JDL1BLQ1M1UGFkZGluZwAAABBhbXpuLWRkYi1lbnYta2V5AAABWFEzcXNQenFUZ1hJUStDYTVTakxJaXNuWXZEbEx0cHRId2Y5WFpNV1AyVzhFVEk3WG9tOGlaN3o2eE1KSjBrM1JYVFJ4ZEZWcHByVXlRc1owTnBYdElYTTdSSUtxZHkra0U2UUtqVk1FampHKzhxa0pHUmZTY0NraUZrQW1VRmRIWHFoVWRtTFFiUDVSYTc0RjBzSU9GU1JJd1Qrcy92cS9kNG5ialpkUEg0OGp1TE1lS2ovUEtrUkx0QzA4Qzl3bTdBMmxDTXc1SndMK1paY2JZc0RnY1c0UmFPcE1QeUtTWTZmc05QMHBlc1NuUDZjTkY1ODZ4Q0lYYkhpQ2dqbjN6dC9GbGxIbWR6UDhocUVwWlRibWFyOThWM0ZOOWczWXpaVm4rSXJTUWZ0V0VxYlpDWUxoZDBWRjdXaGNNZU85YXNIenJhVU5tUS92cmVLelI3QWJNUT09AAAAEWFtem4tZGRiLXdyYXAtYWxnAAAAJVJTQS9FQ0IvT0FFUFdpdGhTSEEtMjU2QW5kTUdGMVBhZGRpbmc="));
        item.put("rangeKey", b642Av("AG4AAAABMg=="));
        ddb.putItem(new PutItemRequest("TableName", item));
        item.clear();

        item.put("*amzn-ddb-map-sig*", b642Av("AGIAAAEAjyMvaawr9SVz2o2aZu9DTapsym/AbELIdz8JPKoWFbxmEQqmUmf1jaMDC91xLfBw5b9qjeCEgb0FmsSXtnT8QhrGrzsCYGwiAq8DVg4rxnSRGdILKzWeYpxJO1Laf1vzow5DIz2FWxMSaRzVYh8nGPoPdO8XiPWb9tp7uLF+s0vjt6UuGcwR+4aOw2Dr+1xL2jO18uKrCxGPtXUP5D0ThZctwiQaamP2Nz1RSHGGatKU2zPcMzp6zoIPIjdnMqX1g28La2IR2mxR0Miq7Mit5EkqYk+s7XdYlTPNhVXifJu9iHvFmsLtc/hJryvLG7hrzI3Bzg2b6mkdL7oVuH2wGQ=="));
        item.put("hashKey", b642Av("AG4AAAABNg=="));
        item.put("*amzn-ddb-map-desc*", b642Av("AGIAAAInAAAAAAAAABdhbXpuLWRkYi1tYXAtc2lnbmluZ0FsZwAAAA1TSEEyNTZ3aXRoUlNBAAAAEGFtem4tZGRiLWVudi1hbGcAAAADQUVTAAAAFWFtem4tZGRiLW1hcC1zeW0tbW9kZQAAABEvQ0JDL1BLQ1M1UGFkZGluZwAAABBhbXpuLWRkYi1lbnYta2V5AAABWFVMWk1LekJhWnV4WHgxSDIvSUtiSHFMMnIwU3lJc1NTTnBWSkxuTlpXM2s0VzYvZkZ1SW5CaHdJdkxLUXFmY2tzcWtTSUFNbzdnd29KUVpneXZzUTZpeFRpS0ZuT1VFMS9aM3E0YnVjSGhKa3VOdmhFcExrZlYxNzg0QW93WFQzYVNEcGtuNUllc2p0ODRZVGdOVEEzUFBGSGZYMktaclBOT0tJWFdTUWtaQk8rK0Zvb0laQW5xQjkxZGs2NFZCMFRyTnRVbXYxcTlkbHgyWklqcFlIUU96aWZha1QzcWV4WVNLRStHSUs2cGdGSzd6dTBMTHRTREpVdnZUcHArSy9xNzMyVjdGY0dhK3VEY2NsUEM4SFdEaWEwN0RNa0hQN3o4WGkwdHcrM3VWU0NmVlA4R2YvUTIrODhyM0x0djRWRms1YUM4OUtlcEVNditZTlBhZXBXZz09AAAAEWFtem4tZGRiLXdyYXAtYWxnAAAAJVJTQS9FQ0IvT0FFUFdpdGhTSEEtMjU2QW5kTUdGMVBhZGRpbmc="));
        item.put("intSet", b642Av("AGIAAABAS+mU+2GCOyieXTCnXN6EW0aJ2q1u0lzYR+0Klp3ie7JKzT50zgGIfTTF7mL4UglTVEBsUGuTDB1InROrNkpU+A=="));
        item.put("stringValue", b642Av("AHMAAAAMSGVsbG8gd29ybGQh"));
        item.put("stringSet", b642Av("AGIAAABAROVxXPL8ZIBOjE+SqmxNuWymmlubdUnMnlVzVAcZvWYQFtkQf7Fw7tgHYILDcn9x1MEsqq60wupRhyRLCJD7hQ=="));
        item.put("rangeKey", b642Av("AG4AAAABOA=="));
        item.put("byteArrayValue", b642Av("AGIAAAAgcEXPxkOed6M21vOTq5vi0KArgXdhtumzZkTxLH39N3w="));
        item.put("intValue", b642Av("AG4AAAADMTIz"));
        item.put("version", b642Av("AG4AAAABMQ=="));
        ddb.putItem(new PutItemRequest("TableName", item));
        item.clear();

        item.put("*amzn-ddb-map-sig*", b642Av("AGIAAAEAUKESqnTKdCqAtM6aDkJGg068ssNWFv811njBVuRK7mzVtmIG5OxLQKr8ycBf/Zm3j2fDnkeLnZwc/Fya9XCTygte4yy1QZSywrSb83uhGFlmLsjGOKcE5ZTMPEMb75+I+8I8OQ3ggfM3EnyaTFQCIfeY+3antQ3augrWioBaoJ3VpoUU+RSA6FOrlVtd01qNO2ZOXCfcX5soh2r60FXZ3fdJZJKvO61xkf4nlZJQkc175bsV8KRHh+125a/KETb+3Gc8uL2aRFBO03fuSCHS97YN7nbevtzM/WdqfXh83N0sBIibHhY73xd5n1sDwKhn9D3madRlzlj6GgwiY6wOqQ=="));
        item.put("hashKey", b642Av("AG4AAAABNw=="));
        item.put("*amzn-ddb-map-desc*", b642Av("AGIAAAInAAAAAAAAABdhbXpuLWRkYi1tYXAtc2lnbmluZ0FsZwAAAA1TSEEyNTZ3aXRoUlNBAAAAEGFtem4tZGRiLWVudi1hbGcAAAADQUVTAAAAFWFtem4tZGRiLW1hcC1zeW0tbW9kZQAAABEvQ0JDL1BLQ1M1UGFkZGluZwAAABBhbXpuLWRkYi1lbnYta2V5AAABWHRoUXFMR29QbkJydUNBa3FpeEROY3g5VEYycEIzZnRobmdZZ21NT3RUQ3pHSmtodVZxbzR6bnRoYzEyZkdjR05DY3UyRit1WC9NRTZ4bFY4UU8zblRjQVlXLzlScWw0UXo1OXB3dXBFV1NhR05aTDhVSlQ2UHhaa2w3WElTMzJvbnhuRVd4ZEJsR2U1a3RadFdSaUN6b0t5S3FZMXRCaHJKcVdWU2xsL0tYY3l0ci9FMk14WjRGT2NZRjlTVmdEeDIvSGtJL2VXaEpkbWFMWU16d3J3RWR0S295aXNwVVZLbUN3T2QxNFYvRGNSQkczM0VpK3hQbWtGOE8xTXJIMG5zeFBCQW0wYXQ3azJnQ0ZBMTBTUmJ3ejhFZFpMeTVlcS9HVTUzaFNuaHlnUmUvT2toWHdWMG5qMlU2YTYyd0lzVWhQdllVR2JIU0VzTkMzNVJmbDkyQT09AAAAEWFtem4tZGRiLXdyYXAtYWxnAAAAJVJTQS9FQ0IvT0FFUFdpdGhTSEEtMjU2QW5kTUdGMVBhZGRpbmc="));
        item.put("rangeKey", b642Av("AG4AAAABMw=="));
        ddb.putItem(new PutItemRequest("TableName", item));
        item.clear();

        item.put("hashKey", b642Av("AG4AAAABNw=="));
        item.put("intSet", b642Av("AE4AAAAFAAAAATAAAAABMQAAAAIxMAAAAAIxNQAAAAMyMDA="));
        item.put("stringValue", b642Av("AHMAAAAMSGVsbG8gd29ybGQh"));
        item.put("rangeKey", b642Av("AG4AAAABOQ=="));
        item.put("stringSet", b642Av("AFMAAAAEAAAAAT8AAAAFQ3J1ZWwAAAAHR29vZGJ5ZQAAAAVXb3JsZA=="));
        item.put("byteArrayValue", b642Av("AGIAAAAGAAECAwQF"));
        item.put("intValue", b642Av("AG4AAAADMTIz"));
        item.put("version", b642Av("AG4AAAABMQ=="));
        ddb.putItem(new PutItemRequest("TableName", item));
        item.clear();

        item.put("*amzn-ddb-map-sig*", b642Av("AGIAAAEAfuTnJmdj2YTv+7PSKT/hVA/HaYJZCuXquvdCFafntAtjNqcQI371menVgbKHLKYZsqaTrCEHskNESd8qzXjJup2uOYdJOl01OKc0qasI+a0XwQspILlhIBo+TJ91/XyUTbqvRExXv+yJ3S1AY7vQmqIIumzy6kcVk0IR0pJjyqCKLbWumJdR+NgITuaowVMGi4BrjE8W3/ucJnB1yh1MZ5kQlINCgW+80MdEmCtxkZ9Lq40CMlhtXoXXXKNtZ5vh/TK0IDEoDMBQKMv3/MoSDxmRjkwCVRjJaD4ofpbmOaubInuVhMMQ2gPkQ8oxNRaNxoqhMv44rgry/sThLLOt7A=="));
        item.put("hashKey", b642Av("AG4AAAABOA=="));
        item.put("*amzn-ddb-map-desc*", b642Av("AGIAAAInAAAAAAAAABdhbXpuLWRkYi1tYXAtc2lnbmluZ0FsZwAAAA1TSEEyNTZ3aXRoUlNBAAAAEGFtem4tZGRiLWVudi1hbGcAAAADQUVTAAAAFWFtem4tZGRiLW1hcC1zeW0tbW9kZQAAABEvQ0JDL1BLQ1M1UGFkZGluZwAAABBhbXpuLWRkYi1lbnYta2V5AAABWG0xKzA3d2o4dUJZYTJyeEs4TkVBUUdnRmVDcWtqYlp5bndMdk92K1ZkdmVsWjZ2bkVqMHI0cnNFbG9SeVdocU5YZWJuMDBReXI0QVhsQW9aektFQWRPTkhxL3A3RWwxdnZ3VHB5NnpmYzF3dkhvc1RVdlRTLy9wRlRvaHptclNsTkFtNFVCb0JLNjJsbUZKTWlYUy9EakNoVzgxQmRvbFZHOHZUb25tTUhJS2Q5RFlJVmtxYUJBTUdYaENuc1NIQWpCUmxQWk5XU3pTZnQyRGc4dGx0b3poY3FwTitsZHNYdTVJSjZoUk44RjlXcW9hUUJLYVY1QXRDdG92dm1BWjU4c0l1SDZnVjVWSllSL0ZzUmZBUlo2UzNJWlErQ2ZsNzRXRXpueElJa2IwWElDMmc1enhTYlhFL0NTYW1pVTIrNm92NjQrSFlvR2tkWEw2ZmpDTUtoZz09AAAAEWFtem4tZGRiLXdyYXAtYWxnAAAAJVJTQS9FQ0IvT0FFUFdpdGhTSEEtMjU2QW5kTUdGMVBhZGRpbmc="));
        item.put("intSet", b642Av("AE4AAAAFAAAAATAAAAABMQAAAAIxMAAAAAIxNQAAAAMyMDA="));
        item.put("stringValue", b642Av("AHMAAAAMSGVsbG8gd29ybGQh"));
        item.put("stringSet", b642Av("AFMAAAAEAAAAAT8AAAAFQ3J1ZWwAAAAHR29vZGJ5ZQAAAAVXb3JsZA=="));
        item.put("rangeKey", b642Av("AG4AAAACMTA="));
        item.put("byteArrayValue", b642Av("AGIAAAAGAAECAwQF"));
        item.put("intValue", b642Av("AG4AAAADMTIz"));
        item.put("version", b642Av("AG4AAAABMQ=="));
        ddb.putItem(new PutItemRequest("TableName", item));
        item.clear();
    }

    private void insertV0FixedDoubleAsymData(AmazonDynamoDB ddb) {
        Map<String, AttributeValue> item = new HashMap<String, AttributeValue>();
        item.put("doubleSet", b642Av("AE4AAAAFAAAAAi0zAAAABS0zNC4yAAAAATAAAAACMTUAAAADNy42"));
        item.put("*amzn-ddb-map-sig*", b642Av("AGIAAAAgABNOeG5nexpOr+MWQa4B48/NZFBV/UTkeSCMbe5j8oM="));
        item.put("hashKey", b642Av("AG4AAAABMA=="));
        item.put("*amzn-ddb-map-desc*", b642Av("AGIAAAAyAAAAAAAAABVhbXpuLWRkYi1tYXAtc3ltLW1vZGUAAAARL0NCQy9QS0NTNVBhZGRpbmc="));
        item.put("intSet", b642Av("AGIAAAAwU2/wlRLHVZxqV4/1FiC8CWSdn7f+wZco9kdFttMyLrhkYBeS7d0dROTlsFK8BY9J"));
        item.put("stringValue", b642Av("AHMAAAAHQmxhcmdoIQ=="));
        item.put("doubleValue", b642Av("AG4AAAACMTU="));
        item.put("rangeKey", b642Av("AG4AAAACMTU="));
        item.put("intValue", b642Av("AG4AAAABMA=="));
        item.put("version", b642Av("AG4AAAABMQ=="));
        ddb.putItem(new PutItemRequest("TableName", item));
        item.clear();

        item.put("doubleSet", b642Av("AE4AAAAFAAAAAi0zAAAABS0zNC4yAAAAATAAAAACMTUAAAADNy42"));
        item.put("*amzn-ddb-map-sig*", b642Av("AGIAAAAgABNOeG5nexpOr+MWQa4B48/NZFBV/UTkeSCMbe5j8oM="));
        item.put("hashKey", b642Av("AG4AAAABMA=="));
        item.put("*amzn-ddb-map-desc*", b642Av("AGIAAAAyAAAAAAAAABVhbXpuLWRkYi1tYXAtc3ltLW1vZGUAAAARL0NCQy9QS0NTNVBhZGRpbmc="));
        item.put("intSet", b642Av("AGIAAAAwU2/wlRLHVZxqV4/1FiC8CWSdn7f+wZco9kdFttMyLrhkYBeS7d0dROTlsFK8BY9J"));
        item.put("stringValue", b642Av("AHMAAAAHQmxhcmdoIQ=="));
        item.put("doubleValue", b642Av("AG4AAAACMTU="));
        item.put("rangeKey", b642Av("AG4AAAACMTU="));
        item.put("intValue", b642Av("AG4AAAABMA=="));
        item.put("version", b642Av("AG4AAAABMQ=="));
        ddb.putItem(new PutItemRequest("TableName", item));
        item.clear();

        item.put("*amzn-ddb-map-sig*", b642Av("AGIAAAEASNpX+4QUwYC+yMsNiQQcYTXiYWWqnkR02KLn1VRH0YLx1wEuFJiOhhqD4a4AhiorExenoP2HHkZdZMJpGGGU9NbupQIr2SeKvV/dkEXrCADvVaaB5O6xIhsN638f9ibknZLEhUt+XAgGDzhPedKwPBr4ZC0UnQCasedHqb9CGXYMCB8P8URbllcJRayM5mf/bv4vfBW7t9uUTd2p6wsiDNG542pw9unP5+/74mZewfgbbp6bp+8KECVLjwTny24LHdSS7XGRb1uJcZsapnhDDamjctjc1jsaaWk2WWUf2YSp/mGNWgk9+m/St/cRwwVr9wjcGpcMld7QDHEEJQmNxg=="));
        item.put("hashKey", b642Av("AHMAAAADQmFy"));
        item.put("*amzn-ddb-map-desc*", b642Av("AGIAAAInAAAAAAAAABdhbXpuLWRkYi1tYXAtc2lnbmluZ0FsZwAAAA1TSEEyNTZ3aXRoUlNBAAAAEGFtem4tZGRiLWVudi1hbGcAAAADQUVTAAAAFWFtem4tZGRiLW1hcC1zeW0tbW9kZQAAABEvQ0JDL1BLQ1M1UGFkZGluZwAAABBhbXpuLWRkYi1lbnYta2V5AAABWEFWclNqZ2RNQTZkcEV0ajhkZU5oVEtXdVhGMlBCclFSeXBKRzRkdTRYWFZlTjRWYVBOT3NwY0dRNFcwVjQ4dVQzeWVzSXlad1JyamwwL2pIby9oOFlxb2Jya0hNOWNUMXQvN0h0VjNRamRzbWZHb0xGL1Q1QXBxaEttY2dYOTZ5V0hWZTYyMlFLRk5Sd3lHaHNTWE9MYnBLOTR4Yk1iWVh5Wkk2d1JwYVl4TTRaaStrTkJQZkpqekxycHdrTXNjN2Y4b3hxV1BZdUdxMzVzSFk4WStXRmc0bUNoMmpQZCtCUWRFeThEaFF3enFHRUtkcW1ObmY4UDFMMzZKbE9NUDVyU1RwUDUzVlVYM0ZVbmVxbG9zT1lGMStwdkdTQ3lScDlJcUZmdGE1N1BEbTkrVkRySnZXd2dXUDh0TVAzdkhDZzB2UnMyV01BN05MSkJRdStYTUdDQT09AAAAEWFtem4tZGRiLXdyYXAtYWxnAAAAJVJTQS9FQ0IvT0FFUFdpdGhTSEEtMjU2QW5kTUdGMVBhZGRpbmc="));
        ddb.putItem(new PutItemRequest("HashKeyOnly", item));
        item.clear();

        item.put("*amzn-ddb-map-sig*", b642Av("AGIAAAEAV0k/mB2e8DSl4lIriyqbYBQbWZDKbiwcfc4ZQB2R3PA+S+hnjiYgwr4zgOXKNk2Dq72M1aIEXzbrej8jVoCSTSiC8pBXxekTqSnUsIYy7ilo8uvoSAN4a8zyfLXxvFPn+ZMwTs48uz7fVe+4MTTIkdd9+sJDTx/ZPEf88mAg3yiQ27cnnqG1N909cvljgjO1ADCcNqfvIMAys3xW5ML4GzdF/G/c/MlRRBMy1rq8HcRC0E09L9BAChfSV3OAwYyns90X5QuTcmpgr5PnY4NFm5WBWYhLwA/nyZDb+Y8e/XAd45i5gLpEpBBxFUiU3X949byFTr/naYFoatBoiWuyKw=="));
        item.put("hashKey", b642Av("AHMAAAADQmF6"));
        item.put("*amzn-ddb-map-desc*", b642Av("AGIAAAInAAAAAAAAABdhbXpuLWRkYi1tYXAtc2lnbmluZ0FsZwAAAA1TSEEyNTZ3aXRoUlNBAAAAEGFtem4tZGRiLWVudi1hbGcAAAADQUVTAAAAFWFtem4tZGRiLW1hcC1zeW0tbW9kZQAAABEvQ0JDL1BLQ1M1UGFkZGluZwAAABBhbXpuLWRkYi1lbnYta2V5AAABWG1sTElwc2ZrSWlLdFJjUWg1anpSY0hIelU2emIyRjB0dTJPNTVESWI0OHlGaVNrTENkUTJYNHZEL0Z6OWYwR1lkYSs1eVdwd2VrNkFCRmxFRHRuVUwwU2MxU2h3c1FOMCt0eE9PaHVYTTlnZjhEbjVmaWpLUVlxaE00N1JMRVlyNzZvak12eGtiR3JIUlIrd24vQjNwb3RKZlhBM3pGYVVRb0xybkJ6VnorR2lNeE04QnJNNnRxN1U5U2k1VDczUVJlRmdUdlluc1F0SVhsWEtMZFhzTG4zaHFlTmk4bzBsMVdxY1ZCSU4rcUNwMWpkZzF1Zmo3K3Q5aFJFbCtWQjd5dktDZ21Ld2J0MTgyVFZteGFZV0RRMGtyS1F4WWdOK0N2MXBlSENmYjZmWjllRW9SdjJ2VXgwZEg4RlpTV3h6K014Q09UVFkwU21jVHJiR1dEOUZRdz09AAAAEWFtem4tZGRiLXdyYXAtYWxnAAAAJVJTQS9FQ0IvT0FFUFdpdGhTSEEtMjU2QW5kTUdGMVBhZGRpbmc="));
        ddb.putItem(new PutItemRequest("HashKeyOnly", item));
        item.clear();

        item.put("*amzn-ddb-map-sig*", b642Av("AGIAAAEAQZii10yqicfBPRRi31KpeTnpe5Dp1oSJAqB7L3uyTWUXz+sXeTqsEFqaIebiTtTCixgK3ZCs9mlM4X1V2iEgFWYuCs8mNoO8oY30vXw17E9EpW79kMn8Tuqr6XQqt+lMorFxKjiYcIkhVbNF6greXbSZ1HQdUGIPLQkACQfzX5I6YWjOCcGm60hXb2dp2uZy9kFceKCTIb0OtryI+7bVXX5YH4Ks9IOKNULWNGbjXEr3J2QdkeLcWZgZQVHtaikXiOlaz+WWyU4h9LaL5DxrojDCu68GXDmOzHYUvHbGCfk3y3hhfkwt9vwucEnA+Y3uDGH3vxUerA8iQ6qUH3m8wg=="));
        item.put("hashKey", b642Av("AHMAAAADRm9v"));
        item.put("*amzn-ddb-map-desc*", b642Av("AGIAAAInAAAAAAAAABdhbXpuLWRkYi1tYXAtc2lnbmluZ0FsZwAAAA1TSEEyNTZ3aXRoUlNBAAAAEGFtem4tZGRiLWVudi1hbGcAAAADQUVTAAAAFWFtem4tZGRiLW1hcC1zeW0tbW9kZQAAABEvQ0JDL1BLQ1M1UGFkZGluZwAAABBhbXpuLWRkYi1lbnYta2V5AAABWEg2Skp6ZUR1RW5zZ2V5K1k4OE1ZZHNLeUx1c09NLzRuT25qRTdxNGVVYTZrRUFXcFpIQjhSMjVFckl3VW1TSXVCbk5rOHd4bmo0cjY2Kzg2VFd2SklHcWlSSTJ3QS9xL0x4U1FxUDY5YWE4YnBiMUhhWHlBZFZpVWhnT3I4MHAvSGpCTm90bFh6VjMvU1h4WXU1cTVxUVEwU3VrR3RkU2tIN1dZeU02YmpyaTE3aUZPQ3F4UzZNNGR6NWRtSU9SbEE1U1NSc0dUcjBmNXUvNWw3dXR0YVFvdG04UzFid3RIZVA2U1R5dWVUYjhLRU5mSm13OFc4K25TVXdhNGtHb3lTUDZ6L0E2NTlrVEc4SkVES2JuWTkxY2tycSswUUozU01OZmtuWG5BRGYreVYrTE1YTDNWMGprQ0hab3VBWktZNWxxelRoK1lTcjE0WGNGWkFlUG5zUT09AAAAEWFtem4tZGRiLXdyYXAtYWxnAAAAJVJTQS9FQ0IvT0FFUFdpdGhTSEEtMjU2QW5kTUdGMVBhZGRpbmc="));
        ddb.putItem(new PutItemRequest("HashKeyOnly", item));
        item.clear();

        item.put("*amzn-ddb-map-sig*", b642Av("AGIAAAEAVRRX8l/eqIeMo7TvQbHI+0Zfh6tbwT5rFJ2zTLYoloudkb8WcBjcHuHEGUhFia6lSKOXwU1cEi/dT4YbQUXf2vzVTxS7jDstYHwHxscVPYNKp7FKzrG/Rym2lF1D78cTn46Zu2/XPw/JgTUhL0Ar7nmmDjUONzzd41QZGr45PFtgBZzGSHyyIpWU2+TRA87quKL71YnrzfbfWoIutJLQ8lAuGlx/gm++09c8PCL60CwUGl6moaVzSYpu/zR+1lxFZ67sWnNrxlsezsQcWUbPJKgeaHfeKDxSevaALTS9dCAjSlE0Sv7XbsdjxW2huNPcPTQCOcqUtetDJ1W2GLa1mg=="));
        item.put("hashKey", b642Av("AG4AAAABMA=="));
        item.put("*amzn-ddb-map-desc*", b642Av("AGIAAAInAAAAAAAAABdhbXpuLWRkYi1tYXAtc2lnbmluZ0FsZwAAAA1TSEEyNTZ3aXRoUlNBAAAAEGFtem4tZGRiLWVudi1hbGcAAAADQUVTAAAAFWFtem4tZGRiLW1hcC1zeW0tbW9kZQAAABEvQ0JDL1BLQ1M1UGFkZGluZwAAABBhbXpuLWRkYi1lbnYta2V5AAABWE5ZbFNGc3FDcDg3Q09ia0FhcnllaUhCNkxEVGROMzZ2NUJBNnc4MEFnOTc0Um9IRkNibE1qcDJLZm80MW1NWjBhUFpXTllRL0RaWVNQRUtnelBsN3FvTktKS1ZweXIweU0rQXZpOXVoNUo2RGpxZTlka2pJMDE2WlFMbkFuQkdGK2ZRdm4wNUV6MWQ5TU82Q2hoQkcyckVxVUJvUWY5RUtjRG84VkJHU1FKaE1RVDROVGZKRmFHN254Z2p4Zjd6VnE0K3QzejNMMDlISHhjQ1A4VUZiUGlFUUpFNWVIOENJeFk0emljVHpIZ05mcTl0OFFXcjNEY3ptck9RSGVDQmNwcThVR3d1ejJ6WTFJd1g0ZkJrdlltTHA5ZnVPSEF2OVEzUXF5dWxpVXNpNlJUREFCMy9GeEtFbXpmQmZQMmlGVU9ycFdKTGRUNWJ1akxpa21mMjlWUT09AAAAEWFtem4tZGRiLXdyYXAtYWxnAAAAJVJTQS9FQ0IvT0FFUFdpdGhTSEEtMjU2QW5kTUdGMVBhZGRpbmc="));
        item.put("rangeKey", b642Av("AG4AAAABMQ=="));
        ddb.putItem(new PutItemRequest("TableName", item));
        item.clear();

        item.put("*amzn-ddb-map-sig*", b642Av("AGIAAAEAMG6vTV+uPAaPmZIGR4I4DbUwIUmivEZQ5sqpK83hue0SArv2a9TtlOTIighJa3b+u/LR/0kxm2Jbx5nqrI7oT0eKSjqJYk1S3w2W/JDPzyk4wwwSoOKH4TLq0KxwXE7QEM4aS5hs92ja6jKPIj7nEJKYOOwHdCdu3Qu2SBmY0VWyj+pUohZv5fzDD81nMeCWU7KmtFsXfKAFFHM2ufCWywXRBXKfYTDPYR87+bfNvbw5W/FmDeu9pdpCIbV66yR3pl4d9+FLoDqbS5yQjKzDI+X5Z90FBaW1xaPCKLcp2l9tRq8q8hfvyXZXrJVisu+/igjqpZ3Tszj9XBmmqLFo/A=="));
        item.put("hashKey", b642Av("AG4AAAABMA=="));
        item.put("*amzn-ddb-map-desc*", b642Av("AGIAAAInAAAAAAAAABdhbXpuLWRkYi1tYXAtc2lnbmluZ0FsZwAAAA1TSEEyNTZ3aXRoUlNBAAAAEGFtem4tZGRiLWVudi1hbGcAAAADQUVTAAAAFWFtem4tZGRiLW1hcC1zeW0tbW9kZQAAABEvQ0JDL1BLQ1M1UGFkZGluZwAAABBhbXpuLWRkYi1lbnYta2V5AAABWFpRSGxBa3NnNVRLeU1NMW1pUENnSFVnc2NoR2VwSWEyMVBsRVJPYk44N0dYWFN1SVJwK1QvZG9qVkxzaGlKdnQrWGZQT0ZGNE5uZTBZNWp5cEVYNXZCSTk0OVFwaEorSnM4U2FQMWNWTlNqV1pKdVUya0k0V0NCZGsxNXN1Z2hGdVFEN254eEVGa1lSQXNsZWl1d2x3TnlpN3FCOTVSMG44eUVWdmFHNmgxc0RXc0c5QlpxVUVCUXZrb0NKTDhFeWU4RmxUMkRZbkN4UDVmL05FYlJkTGZKYTFZbzI5Q0VWMDF3YlZ0ZFpYemhxZXRBc2ZkYmRnTW1KNXFySTRlSkxBeERwQm5jeVY5Z0dKT0xvV21BZTN5YWdveU9MalRaYkVWUkV3dDN2QnhHaGR3K0M5QXVqVitsblNYWjM2czR0Tm12dWxDeVlaTEYxWHByUEtGNlJYZz09AAAAEWFtem4tZGRiLXdyYXAtYWxnAAAAJVJTQS9FQ0IvT0FFUFdpdGhTSEEtMjU2QW5kTUdGMVBhZGRpbmc="));
        item.put("rangeKey", b642Av("AG4AAAABMg=="));
        ddb.putItem(new PutItemRequest("TableName", item));
        item.clear();

        item.put("*amzn-ddb-map-sig*", b642Av("AGIAAAEAed4gAI82hqUpvoUH/glIJXIbasq7CDMbcfm2u/fojO+3FsujnsCRCcIJZIe6ny3ExNC/o272WzUL+Tw1tFnM0VYcS1aAgpdJiTyX4LFPp4uJRlutcxDWCOBpAVh+Ma/oIQDAgxlm1EOcKiWyxhyXm3Bjm8c//rV/YyMkm7NpqK99zCfbgnwI/ezGvEaJe5L3N4eLZBAV9BG7B6if9uvSvCWh3NABr9XNeaXLCHC300ENCk8iUNJJASi1sGQnlTR186Ix8s4DPCfZJbNwWlHrbupgmBq+AZRffbU059QrLfvzdxpaRtHIlDxQwmvk8C7EU2kUuLGyEA8XSdiT5y2fRw=="));
        item.put("hashKey", b642Av("AG4AAAABMA=="));
        item.put("*amzn-ddb-map-desc*", b642Av("AGIAAAInAAAAAAAAABdhbXpuLWRkYi1tYXAtc2lnbmluZ0FsZwAAAA1TSEEyNTZ3aXRoUlNBAAAAEGFtem4tZGRiLWVudi1hbGcAAAADQUVTAAAAFWFtem4tZGRiLW1hcC1zeW0tbW9kZQAAABEvQ0JDL1BLQ1M1UGFkZGluZwAAABBhbXpuLWRkYi1lbnYta2V5AAABWGZpVVJXYnJtWXMrNllPUnYvUlk5NXM0RjhOaXBtS0V2MFVBV2FBVUhvQTlJSlJ1WnhGakNkUk1PWE50S0k5RW8rUjc5SXNVTXF4dm1wVjJLK2M1SzBKUjJDclZ5Vmw0ZVd3STRJekM0d3I0d0xPV0k0djU2S0tGeTN5TXIzSkpvTE9BMVdUUVBaRGl4Z0x5SlNoYlJsbjNaODJIOVFYT0hYUFdXR3VaN3ZDTm5HbVhnZVhSSVZlTkYrREFnZ2sxdDFydEU5ajJ3ZDdxZDdOeDRCb2pjM1JKa29STXJkRHFycXpMWjBsWUNPZFdvbVl6YXh5dGZnNzhkVlh1bVFCMHRvM3pnaHRDNUhTb3BRRzgwNk5vWG1rdXgyNTdHU0dWNGhERkMweGgrczB4SVYyTTZhWURYS2VnQWVJbjY0R0ZJYi84NFBvcWxoeEhQOWRKcUQ4NVBFQT09AAAAEWFtem4tZGRiLXdyYXAtYWxnAAAAJVJTQS9FQ0IvT0FFUFdpdGhTSEEtMjU2QW5kTUdGMVBhZGRpbmc="));
        item.put("rangeKey", b642Av("AG4AAAABMw=="));
        ddb.putItem(new PutItemRequest("TableName", item));
        item.clear();

        item.put("*amzn-ddb-map-sig*", b642Av("AGIAAAEAMaO/4MFm20VFjw2ER/jpwi6iR2VBYKp+uwdJH+/CZv1NlwMDp+9t7MHu9DArLIzQlHjUQ905a8FV9LeNHcDD29CNDXz3u0I6u7Rznhoa78N6fO08aDdHn+MtLzoZaKi7dpJ1M2xNzAM/3x2dTkLiCGKuAOnpmk4SSG2vKu1OssM4e9VTwWgdWgUBHyMef38fEoT55XRy67phr4e77kVesV+X/lM+JudGuzxZgbrFsFVgy98DQ2SJF4gpNKkNOeWKFIomT8bEukxECfi0Vyk/m7PSMKgvF5JBBNQYEt7HXRUo1lVmUc7WvBHYU4dVkz2oQZn06F//IAZo+qsmqOM12Q=="));
        item.put("hashKey", b642Av("AG4AAAABMQ=="));
        item.put("*amzn-ddb-map-desc*", b642Av("AGIAAAInAAAAAAAAABdhbXpuLWRkYi1tYXAtc2lnbmluZ0FsZwAAAA1TSEEyNTZ3aXRoUlNBAAAAEGFtem4tZGRiLWVudi1hbGcAAAADQUVTAAAAFWFtem4tZGRiLW1hcC1zeW0tbW9kZQAAABEvQ0JDL1BLQ1M1UGFkZGluZwAAABBhbXpuLWRkYi1lbnYta2V5AAABWFJNM1NvSmRpdUp0ZkpsUUNFeWtRUy9NS3MvbFZmTlFYK3U1OXhMVkRZTC9PcmFBeFR2em1HS3hCcjFLc2ZCZU4wQW82YlNEb21MSDdsRHdNSGpRZjVCZnQyRlliRUc4bm5rSnBhaVpHYnBCQlBUVHh6SURGbkZJZ3JMRnpTT21UanRTK2ZBTVpjYXJuNGVvTFJvbEd6OE5FbnNrQVBUNWV0QkFIMXg2UUJjQ3h3WUxtOENWeDZ2T3JyZDJUUThONTZ5WEpMOWpZZzFNczdoN3dYSitDV1lVRTI4ME40a3lId1ZCSk56aHVNNkFFdVkxcDdNNEtqSFpycHBXWm9QM0FCYmk0RW9GaCszdjdXYnNCbzFpSFltLzVSQnBqTFZyRW9RNkpuMDlHSllVMDNvM0dRcjIyaVozK3YrUVVnLzNmUWZGUy96UGsxS3NVQlpPOHRWNnhyQT09AAAAEWFtem4tZGRiLXdyYXAtYWxnAAAAJVJTQS9FQ0IvT0FFUFdpdGhTSEEtMjU2QW5kTUdGMVBhZGRpbmc="));
        item.put("rangeKey", b642Av("AG4AAAABMQ=="));
        ddb.putItem(new PutItemRequest("TableName", item));
        item.clear();

        item.put("*amzn-ddb-map-sig*", b642Av("AGIAAAEAfq5jMK7LBRwa63vh+Unxjxxuj8ugx/l0jqRalmWNql+k/RTz3lxsNCTFh1svGTP4QZTLL/GghdZGmGH2Pb82M45ExGsvZoVzkdQ6Gc/y8NNCMkD98pZyYeWchDazrqC1EnB+IoYbuG5vQF5vCwR2jEfd42bu+YnPMy3ackMEF9fDamQdHsAwfDDFsshmePA0Q4RMOaBUu48YhrDhSYPXH2DAv8lwPqh4lWGOrtalV5MFCvVzFO5ss47XDeI5zjafkwoJQPU5b44cvvLXeq56p0cWn9uFt2XMZ3HBHxDOOOAUkqNKShlaQ3m39SdU58fN50MLrc3G3mUjbttFBBE5AA=="));
        item.put("hashKey", b642Av("AG4AAAABMQ=="));
        item.put("*amzn-ddb-map-desc*", b642Av("AGIAAAInAAAAAAAAABdhbXpuLWRkYi1tYXAtc2lnbmluZ0FsZwAAAA1TSEEyNTZ3aXRoUlNBAAAAEGFtem4tZGRiLWVudi1hbGcAAAADQUVTAAAAFWFtem4tZGRiLW1hcC1zeW0tbW9kZQAAABEvQ0JDL1BLQ1M1UGFkZGluZwAAABBhbXpuLWRkYi1lbnYta2V5AAABWG1CWUs5Z05nRTBMYU9jL2NvaTZjdkJCbzlLVW45ZVpzbmdyZVE4UnR4R25OTVQvbkN6R3REcWlXajEreVd1REpHU1dlb1RBQysrYTR3KzJpNUx5WkV2bFg2K01uVzE2L0NyZ1VaWjBlcnp2eFVseVFDYU9ZbmJhcHM0UFR0NjdZYWxBaTRXaEE3Mjc1a29LQVltYzVBSFg1cFlnUWh3eFVzcys4ZDlJRkg1bGlhUldWY3hVTVQrMzBZcWhERkQ3bnE4TXVyZDNPY3h3eUljd1EwZDZacDdvRCtHMDRNeG5tWjM0cjUvRTRHYU5JYlpNVGE5VDBWUW1qYmJEM2piallKMWlrQkduRnlwemd5czJJVU9lREJ1SjRxVTJBek1nM3NqbkpIcmNWcGRzU2NQcnpISnJkZEtNblE5V2Y2NVkxSTFWNUpOOU9RbUtyQ1pxZ1VuVUtuUT09AAAAEWFtem4tZGRiLXdyYXAtYWxnAAAAJVJTQS9FQ0IvT0FFUFdpdGhTSEEtMjU2QW5kTUdGMVBhZGRpbmc="));
        item.put("rangeKey", b642Av("AG4AAAABMg=="));
        ddb.putItem(new PutItemRequest("TableName", item));
        item.clear();

        item.put("*amzn-ddb-map-sig*", b642Av("AGIAAAEAraKHapJyc7wtw9Qzbr4c4AbRlLAT8p0rkrN+gm3JFSJwFLHtf6dHBQv9tveVRNo4VMeV+PJDbWDcPDEivK4Vq5N9BAlveRSx+d9Mj/ueK323VUIGynQwdI2PO0J4pncTvFIH/VMauMcCItOlmaOV/pKogUIYLqEGdgqPd5M6TuL0Gxki9i9lzZOg10yJZjTIg33I4L1C04xQVZ7c9gcyQB715y0TwF+0oXs1EG2KtUdF2oS2yqCb67v226gdj5aoFNUzfijy7v3s3cRMVA0fQKwpda+d9Rj5NzkvwBo43oKFFh58tl6FbRa3nN9Jj9cxWGtTSIlVd9RQ+vttzObdIg=="));
        item.put("hashKey", b642Av("AG4AAAABMQ=="));
        item.put("*amzn-ddb-map-desc*", b642Av("AGIAAAInAAAAAAAAABdhbXpuLWRkYi1tYXAtc2lnbmluZ0FsZwAAAA1TSEEyNTZ3aXRoUlNBAAAAEGFtem4tZGRiLWVudi1hbGcAAAADQUVTAAAAFWFtem4tZGRiLW1hcC1zeW0tbW9kZQAAABEvQ0JDL1BLQ1M1UGFkZGluZwAAABBhbXpuLWRkYi1lbnYta2V5AAABWEt3NUpWUEZBVitPUkdYWmJBSFQ1eVhFMFhGdGo2NzZkOUVtaEo5dDJJVmF5VjIyZG9PN3JJUlZ6d2ZJOFdtbWxGeUZ5aHpwNlpaNk8wT1dhejhybUc1Vmdwc0o0cHRLVWU1Y2Q4d0VxeDQ3eEJEeXgraTNrUCs5bFhQQTdnc2VORk83OU9URkJCbG1qUjJnYU1OaTNjOXp0U3VVZjNpaGY5cTZ4TzhLcDRYL3F4dHVpNnhwaXBCK05xQVFjNlpYSHR0TVNDVXIvNTIvTjFBc0p4Nm1TcGsxTjFXQjdlY2VKVk1KUDYvSUh2Vm8wSUF2aWxicUVPVHY1OURYM2JzVEpTZmRUSlkrUHF3dzVRVXFLTXYxSEgxb2xMQnpPejVTZ3lsSlBlSzlFeGM1L1hnZnpXTWd1VzNlbzVpYlREUXdrM0FzSXk1R1ZZZnRQZmc2Yjg4NTArQT09AAAAEWFtem4tZGRiLXdyYXAtYWxnAAAAJVJTQS9FQ0IvT0FFUFdpdGhTSEEtMjU2QW5kTUdGMVBhZGRpbmc="));
        item.put("rangeKey", b642Av("AG4AAAABMw=="));
        ddb.putItem(new PutItemRequest("TableName", item));
        item.clear();

        item.put("*amzn-ddb-map-sig*", b642Av("AGIAAAEAMlADNyM2Rd+jSXzd/NgK53qnNIWrjOswmITkLKy6wmuP7tyYZZfdz/yN9rv/AeaDF0SKxQiTkIuWxtibyATiEFLc2DdulIx8Kl2ZydWSgvEI8ZCrKDNjhX8auceL2XZwqUQEWgNIoSRj+TpXZNwxygg0ZyT9d+PP8RT3yM64/9A2nW9WHMWK/ASwGJVHo1dlDzdspvcUCEtkO7U4ey9q25HX7YDx5p+yMxUH360fDuDYnXIdMyOSwPFO6LkcBpkxWSHsgB1jSZ9bVVceXi+mM3sUL+aLkUd/sP9Yl5/mOKASpJezNKcetAdSaC7VSKJ1PMbcEDSmK6XqblnNGF1L/Q=="));
        item.put("hashKey", b642Av("AG4AAAABNQ=="));
        item.put("*amzn-ddb-map-desc*", b642Av("AGIAAAInAAAAAAAAABdhbXpuLWRkYi1tYXAtc2lnbmluZ0FsZwAAAA1TSEEyNTZ3aXRoUlNBAAAAEGFtem4tZGRiLWVudi1hbGcAAAADQUVTAAAAFWFtem4tZGRiLW1hcC1zeW0tbW9kZQAAABEvQ0JDL1BLQ1M1UGFkZGluZwAAABBhbXpuLWRkYi1lbnYta2V5AAABWG9SMjRkU1FWK0lNTXZIY0c0emlxWmpNLzgxQ0Y3VENJQk5HMFJEdjJlRDlLaU93MGNRdEJ2ZVgxamlPS0J4eGR5cThVeGQ4WnRXYnZUTzNWNXkwRno1aUY3TTBMK25TeHluei8yZ1NRdGg2UGZKZ1MyYzVGQTZBeFBRNkFTNmNsT3FmQTlGa1d4ZkdNVHkrRExSVm9DaDBFbGlyY0JIcGNZQUNqc3lWMkd3am1nZEpaVCtKeDAzZWZNV0RpdlNmWlI3cW01dkwzemhhTUZJU1gyK2dBdFZKaXpmQ2wxbllBYklnMjZzbHoxMkdjcjY4Z1VGaGM2ZlhvWVRMZTlNQ1dzRHF0UTh1eVJDMFBQNUZwWERqdVFEdzR2ZzJGZ3NFQy9scjRKY3FhYUJHTldMNTlHNWRpc091NXNTS0FFZkUyY0NIV2Y1TFpEU2xWamVPSnBSdzF2UT09AAAAEWFtem4tZGRiLXdyYXAtYWxnAAAAJVJTQS9FQ0IvT0FFUFdpdGhTSEEtMjU2QW5kTUdGMVBhZGRpbmc="));
        item.put("rangeKey", b642Av("AG4AAAABMQ=="));
        ddb.putItem(new PutItemRequest("TableName", item));
        item.clear();

        item.put("doubleSet", b642Av("AGIAAABAR/EUfopsFa4thzJjPi5wDKrD0xkQTxsqNBPQThG+FzXVtVojpI8hd82BLjWYjjTH6t20+rvutk9tXnfkywoygQ=="));
        item.put("*amzn-ddb-map-sig*", b642Av("AGIAAAEAp8q1hUKl9fSZWKI8tvL2kxU8rPnTRACedH4snUgOB5u6ZQ/sTOI9fbRdbStCWnybYiAfGAcxrpDKED/t3tWGcWqUVWzinfDOi3qPrGi51JKE02j9Gl0wzgrVe65wvCDfrvaTGggWPkqOKyqgdzT8HPFVoGXGYdAFSo+v5XCXs8/PxWxWkYxJvFXprzQ56FKV0IFG+HZmpoltqI4cv+46NdcIerEd6W8J1LhjZU4PKID/6QwPLa0iY8LVC9pWyqR9GVZDQ/bRko52KrUp1BYwXyrmu7CyN/jWT+nacxMMHJuIkCsXBGFV3+CEbbxYXvjTg89d/rD++OBWoM6Celm3iQ=="));
        item.put("hashKey", b642Av("AG4AAAABNQ=="));
        item.put("*amzn-ddb-map-desc*", b642Av("AGIAAAInAAAAAAAAABdhbXpuLWRkYi1tYXAtc2lnbmluZ0FsZwAAAA1TSEEyNTZ3aXRoUlNBAAAAEGFtem4tZGRiLWVudi1hbGcAAAADQUVTAAAAFWFtem4tZGRiLW1hcC1zeW0tbW9kZQAAABEvQ0JDL1BLQ1M1UGFkZGluZwAAABBhbXpuLWRkYi1lbnYta2V5AAABWGlzOUlLakQ0dEZWcWxvVVc2QW5ESUhxbVRNa3djNnQvVkhoUnQrbVk3SGpTUU5UZ0hIbkJKOGZsWDF2QlpGbmJYN1FsMVBjMEViN0ZWSGJKbXV3SWp6L2xnVzF4K0FZT1RVYStvRzRNZEJJK2ZVUVkrMU1VNFh5RG9EVmN2TW8rUDFkL2hGNGxPcng0T2xOV3ovVm8zUzY0M1VVNitrWU43SVVCOC85RGp6Z1NTZkRIS3E3bEFsMEVCZm1MY3NtRkpmUFFLbVJ0WjIrbXRRNUhsV1Fubi9DVnQ3bmZGTGhEV1NEbEtYMm5uSVlCVmdrMEJHQWFOaGJFbVNqREFaaEJ6V1M4N2pOVTJnMGJkaHlyOHRNY2c1TmlCM1F5TDdPWERiS0orTXlrUmJvNlA0Vm9NY1lkTHk2OUdCYWM4WjZFQjFkNGdmTUtxNklnazRhelp0aDhVdz09AAAAEWFtem4tZGRiLXdyYXAtYWxnAAAAJVJTQS9FQ0IvT0FFUFdpdGhTSEEtMjU2QW5kTUdGMVBhZGRpbmc="));
        item.put("intSet", b642Av("AGIAAABA0Sj/sNRaozw9XKYKDVNLW4vFoEB0e76L6awEUvtOCBA8pL77j2CUtHIiBDB1HIf2pBb/i+oNF85lwptguFE6rA=="));
        item.put("stringValue", b642Av("AGIAAAAww9aZNvR3yzxbGhub/qkSk+AK8+ltsl15eH9e37CudODt8OjztQo0YVwrP0o+JS3y"));
        item.put("doubleValue", b642Av("AGIAAAAgisjjsah8rGZ78Af2gnP2yhWZ8Wq6PDLb5aP312l5zl0="));
        item.put("stringSet", b642Av("AGIAAABAgW/RgnOMZM9nZk7PRQ4qQwakhReiS2oaQC3OFTQkigx8nO+KAGlpdqSKZGV6vtVyDcgEtmA8zcphXizTCZGQiQ=="));
        item.put("rangeKey", b642Av("AG4AAAABNw=="));
        item.put("byteArrayValue", b642Av("AGIAAAAgGjoUlvWLhyxuSzUKtatZd4r/rUudD7hsajyQ0oOzjZ8="));
        item.put("intValue", b642Av("AGIAAAAg165MtGUmgndEpx90SVAKf7dSTkmwS0wrVmubkpMBxl8="));
        item.put("version", b642Av("AG4AAAABMQ=="));
        ddb.putItem(new PutItemRequest("TableName", item));
        item.clear();

        item.put("*amzn-ddb-map-sig*", b642Av("AGIAAAEAjKVKU8uHbhAg8vlU8WqK3qIss6XKPJQXATVwFlkqw5N7RMj0yjQWQ5pJC81sdkXp3NmIgF9Wnavzl5TEVB6R4v/cwxT85ih/kMN7NDOXU5OEkQUlzCRCZ3U6wVvWgFbbI68r42LNPav+uuWBB2/cp9Uu/4VbsOQC7IjEdWIPkir+5BP7HBFg78cs9YgpkDuw2J8+4KLj4z5CsSW6dPjhmbPolKmhn8DinezJ6bHpRFmP0ry75HxMUTu2wInwHD0mCpK1TXWJ3t8V1+UJkNHHpD6j78UhNH9Ky2h9pgj+7Gml0pnZ9t0skUCXNcBLf0Pj3RsqvQuYrU6f2tV8DDxm8g=="));
        item.put("hashKey", b642Av("AG4AAAABNg=="));
        item.put("*amzn-ddb-map-desc*", b642Av("AGIAAAInAAAAAAAAABdhbXpuLWRkYi1tYXAtc2lnbmluZ0FsZwAAAA1TSEEyNTZ3aXRoUlNBAAAAEGFtem4tZGRiLWVudi1hbGcAAAADQUVTAAAAFWFtem4tZGRiLW1hcC1zeW0tbW9kZQAAABEvQ0JDL1BLQ1M1UGFkZGluZwAAABBhbXpuLWRkYi1lbnYta2V5AAABWEJxTHVkd2Y1bFhPWUNTN3hJUnkyclJBMzBVZUk4WGYvd01yTFNMNG9zNHFvNjgyY29tNGx6M3IvOTE4bFFiMDhmazRZMktqUk1EdFpydkZsRVhrN3lDam85QmQ5OTNWMm1zeXBTUGIzYkt2R2d3NXFzeExJbWdDOUtrL1kvNkJRd0NUM3FxVWZ4aWlLZmdqNEs3ZHBsTXZJVFlPZzRlY29nMXVKQkl3cENhWE5YYTlWZkI5ZDlWRHg3bUhHSnpROG5vekdJUDdzU1dUaWRzakI0NW1NVXU3dTkwLzRoYTR2VGZ6czQ4QmhVZnZMczNvKzlIRmZxVks2cW1va3JlRWFvVjhPVFdIYThxMGxSekYwZ3J0M2hDamUrREdvNVpFcnUyclFmdmgvK1prTlpZbkw1V2p3Y2VhcEJnT1h3UDBPYjA0TWsrWldzZkdLRG5uYlF6V25iUT09AAAAEWFtem4tZGRiLXdyYXAtYWxnAAAAJVJTQS9FQ0IvT0FFUFdpdGhTSEEtMjU2QW5kTUdGMVBhZGRpbmc="));
        item.put("rangeKey", b642Av("AG4AAAABMg=="));
        ddb.putItem(new PutItemRequest("TableName", item));
        item.clear();

        item.put("doubleSet", b642Av("AE4AAAAFAAAAAi0zAAAABS0zNC4yAAAAATAAAAACMTUAAAADNy42"));
        item.put("*amzn-ddb-map-sig*", b642Av("AGIAAAEARJpKAoXXSPxKUlYA3zxTAMIbaXJoIjo6Mq+Sy4CbGHQzsf4UkWEz157mdT+OCwMNGBUXUnvJhX+9GhTB/dU0pCkGrC9p7BwazNaAhGO4fcDPEsVP5LTSAAs5ZEw1CdopWQsK+mVMAw12XwO9NeOW/cUG7wDZ/u4Y01ejnO3nLaMIi24riIQRiMduk8AJTg41lU4rcSxDKWUn1pBweolLTX6W8zo50BcmAn/qeThVVQBoqDgJYPyUZ6UIDDl3OSg1Ujsn2c0JgzlAtxddWQ22uHSRKUbv7tURIO5N7WmK3RhUnumACekG4acXt9kAn8PBWj2Yvwr4Z3+w908RET7+vQ=="));
        item.put("hashKey", b642Av("AG4AAAABNg=="));
        item.put("*amzn-ddb-map-desc*", b642Av("AGIAAAInAAAAAAAAABdhbXpuLWRkYi1tYXAtc2lnbmluZ0FsZwAAAA1TSEEyNTZ3aXRoUlNBAAAAEGFtem4tZGRiLWVudi1hbGcAAAADQUVTAAAAFWFtem4tZGRiLW1hcC1zeW0tbW9kZQAAABEvQ0JDL1BLQ1M1UGFkZGluZwAAABBhbXpuLWRkYi1lbnYta2V5AAABWFdZOCswY2ZZaFkyT1Fjek1Ya25YZDQ3UXZxZUxsQk82dTJvTS9Id1phZVVFb3FjNlhtNVd1VjJ5V1pZNW5qREorS3BrdGhaQ1RsTnU2QXdNcmpBbm5WVVZZdHkxWmtlRUVMWU9UZmhzN2ZGTkdqQ0d0a1FRWEpQb2lLOVB4OEt3N1VRdDAvTXJTY2k4Ylk5VHgwVmFVQ0I1MDV5ZG1IN21WeDN4bkZlVXRZekMzNWNlMEt3cDdqaG1iRTFTZVlocWxPTVRCRE1sQmZvcTJRSG83bmJUNHo0V0Z1RlhZbHdSMVJnRDNsK2cydjl4dkFIekF6SDZmeW5qTFM5c2RXYUc1Q0FESElqYXRJMmlqeGh4NXFmeEtIRmFBN1JraC92UEdFdkdLdEhsdkhBMmlwOGtRTTRmcVpVaC9lU2RhT3EzZ2RSR1NRUTE2aFZMT2JlZkNJZHlmdz09AAAAEWFtem4tZGRiLXdyYXAtYWxnAAAAJVJTQS9FQ0IvT0FFUFdpdGhTSEEtMjU2QW5kTUdGMVBhZGRpbmc="));
        item.put("intSet", b642Av("AGIAAABA1y82dQGX/4gbSZ9okCbwkWYt35CHvGRlHSwKR1K/NV/+AQ04tEWx3+HNze/t78qIa5ttNWw6gzFl6lop6iaVmQ=="));
        item.put("stringValue", b642Av("AHMAAAAMSGVsbG8gd29ybGQh"));
        item.put("doubleValue", b642Av("AG4AAAACMTU="));
        item.put("stringSet", b642Av("AGIAAABACNJWkRL3Rjm5akaVNBUizbKtQ13INgSUwMNQR+KYYKJPJQJpAQIrk1u8PALl7V7JvDEOAdwcv+gNjFT+WQGniw=="));
        item.put("rangeKey", b642Av("AG4AAAABOA=="));
        item.put("byteArrayValue", b642Av("AGIAAAAgfqCji3Cm6TKPeE6Huejc22X/1746VPMPVwrkqvNtGHw="));
        item.put("intValue", b642Av("AG4AAAADMTIz"));
        item.put("version", b642Av("AG4AAAABMQ=="));
        ddb.putItem(new PutItemRequest("TableName", item));
        item.clear();

        item.put("*amzn-ddb-map-sig*", b642Av("AGIAAAEAUKESqnTKdCqAtM6aDkJGg068ssNWFv811njBVuRK7mzVtmIG5OxLQKr8ycBf/Zm3j2fDnkeLnZwc/Fya9XCTygte4yy1QZSywrSb83uhGFlmLsjGOKcE5ZTMPEMb75+I+8I8OQ3ggfM3EnyaTFQCIfeY+3antQ3augrWioBaoJ3VpoUU+RSA6FOrlVtd01qNO2ZOXCfcX5soh2r60FXZ3fdJZJKvO61xkf4nlZJQkc175bsV8KRHh+125a/KETb+3Gc8uL2aRFBO03fuSCHS97YN7nbevtzM/WdqfXh83N0sBIibHhY73xd5n1sDwKhn9D3madRlzlj6GgwiY6wOqQ=="));
        item.put("hashKey", b642Av("AG4AAAABNw=="));
        item.put("*amzn-ddb-map-desc*", b642Av("AGIAAAInAAAAAAAAABdhbXpuLWRkYi1tYXAtc2lnbmluZ0FsZwAAAA1TSEEyNTZ3aXRoUlNBAAAAEGFtem4tZGRiLWVudi1hbGcAAAADQUVTAAAAFWFtem4tZGRiLW1hcC1zeW0tbW9kZQAAABEvQ0JDL1BLQ1M1UGFkZGluZwAAABBhbXpuLWRkYi1lbnYta2V5AAABWGxjNFJBeDhFbllhaEk2ZFVaOUpQeDR4TVhpcEVpUzVxK25jMS9EQ2gxQXhwMXJIdjdPTUREWVV0cnQ0Z2djTjRwS2wvZi82WlU3aUE0VFZRZnFFMnNaTVJWSEVrUmR3ODFSKzNRMHJPVGthK09kN3BKSWNVOUprOTczM1orK2t2ZlhXNXlKYlZwQ2diRmV2WjhGS2NDdXZEMFE4WGltR1NTa1JXRXgwY2lHbG1mRm03MEs2aEd0ZW5RU3prZ3NBSnBCc2pMVCtYbXUwWjBiOU43b0hrWFRJZHVmd3pJa1lKSitBMW5ORG1nbEVhM2U3Mm1tMFBCRHJpVVlMUFhSaHdXQVo5TnRaSUF3ZkwzeFlMNGI1WUFqaGdJMk5KYm03YnRYb3F4WkdlWmdONkRyWkZSNGEyTVBBMm56OXpYNXFsQWYycVdMc3Q2SUlHbUlDeTVEWk12dz09AAAAEWFtem4tZGRiLXdyYXAtYWxnAAAAJVJTQS9FQ0IvT0FFUFdpdGhTSEEtMjU2QW5kTUdGMVBhZGRpbmc="));
        item.put("rangeKey", b642Av("AG4AAAABMw=="));
        ddb.putItem(new PutItemRequest("TableName", item));
        item.clear();

        item.put("doubleSet", b642Av("AE4AAAAFAAAAAi0zAAAABS0zNC4yAAAAATAAAAACMTUAAAADNy42"));
        item.put("hashKey", b642Av("AG4AAAABNw=="));
        item.put("intSet", b642Av("AE4AAAAFAAAAATAAAAABMQAAAAIxMAAAAAIxNQAAAAMyMDA="));
        item.put("stringValue", b642Av("AHMAAAAMSGVsbG8gd29ybGQh"));
        item.put("doubleValue", b642Av("AG4AAAACMTU="));
        item.put("rangeKey", b642Av("AG4AAAABOQ=="));
        item.put("stringSet", b642Av("AFMAAAAEAAAAAT8AAAAFQ3J1ZWwAAAAHR29vZGJ5ZQAAAAVXb3JsZA=="));
        item.put("byteArrayValue", b642Av("AGIAAAAGAAECAwQF"));
        item.put("intValue", b642Av("AG4AAAADMTIz"));
        item.put("version", b642Av("AG4AAAABMQ=="));
        ddb.putItem(new PutItemRequest("TableName", item));
        item.clear();

        item.put("doubleSet", b642Av("AE4AAAAFAAAAAi0zAAAABS0zNC4yAAAAATAAAAACMTUAAAADNy42"));
        item.put("*amzn-ddb-map-sig*", b642Av("AGIAAAEAPOVybkDUXTky3BszXwOiehdzQnXrOoFsVz9l6o9hxXSBQ30LzwwNSNe2UxGZsZGfnHW1BWhg+T4ycxdcXwImovTRRUNUAn1RFU1nJLZaVvAw9FSvDbRWbk4oTiyv3kr7NiCgCQfKOM0H1eUi6tDUYdnR5kPwP2aAyPVtJE0oLR5g2s+09IoOs5FSipYcPOtlN0rT5fOtMCEe2goCIMyluerqISBYmCnLrpg4fhWpQQTvCFuSCccJC4zoQjFrSQAd4hBHlS+xsCmXi1KS3ECwK2bRutntUzZJaeFjFpEn5y7CV0Y/9SuK5fc4QO/XBkubGhiHU74199/etB11rnETDw=="));
        item.put("hashKey", b642Av("AG4AAAABOA=="));
        item.put("*amzn-ddb-map-desc*", b642Av("AGIAAAInAAAAAAAAABdhbXpuLWRkYi1tYXAtc2lnbmluZ0FsZwAAAA1TSEEyNTZ3aXRoUlNBAAAAEGFtem4tZGRiLWVudi1hbGcAAAADQUVTAAAAFWFtem4tZGRiLW1hcC1zeW0tbW9kZQAAABEvQ0JDL1BLQ1M1UGFkZGluZwAAABBhbXpuLWRkYi1lbnYta2V5AAABWFltNUt5NEFSaTZIZ3ZxQXVwMkcvM2puWFBXOHdoRGRpTTE5RG9OVlVTenYvU0F2Q1pScnNnMS9IM25jWVRYY2Fvc2wrU2xJc2NQSVlDTXBVYmhmd2F1aFM3ZE1TUEFqa3FaZnFpb0FLbmMwOWFGR015RHA2Qi8zU25VRm04TGs2Mit3S050R0pyclA5cTh6TFBsYWtJSzE1OGZwM1p6aFk2L0xtVjFrYVBoUms0azkyZGdFOHBMRVZzckVZZXVrYUdleXBFKzFaRnJCc2kraldoWVdIeHRNSS9kUzNqTnJYSFhXblVhV3pwNkQ5YmlONDk0YnhiRlR2b2s5bnk2R1o5ZVVIYXFPdDgxcDdSR1ovUHkwT2hLdThYQVp0TlJWRG1VZTc0T0prMkkzNjcyQzdheVVXeGRZOVB5ZThZcnRaUHY2em5RYlVvVFRybHRPNG8wbDFkdz09AAAAEWFtem4tZGRiLXdyYXAtYWxnAAAAJVJTQS9FQ0IvT0FFUFdpdGhTSEEtMjU2QW5kTUdGMVBhZGRpbmc="));
        item.put("intSet", b642Av("AE4AAAAFAAAAATAAAAABMQAAAAIxMAAAAAIxNQAAAAMyMDA="));
        item.put("stringValue", b642Av("AHMAAAAMSGVsbG8gd29ybGQh"));
        item.put("doubleValue", b642Av("AG4AAAACMTU="));
        item.put("stringSet", b642Av("AFMAAAAEAAAAAT8AAAAFQ3J1ZWwAAAAHR29vZGJ5ZQAAAAVXb3JsZA=="));
        item.put("rangeKey", b642Av("AG4AAAACMTA="));
        item.put("byteArrayValue", b642Av("AGIAAAAGAAECAwQF"));
        item.put("intValue", b642Av("AG4AAAADMTIz"));
        item.put("version", b642Av("AG4AAAABMQ=="));
        ddb.putItem(new PutItemRequest("TableName", item));
        item.clear();

    }

    private void insertV0FixedDoubleSymData(AmazonDynamoDB ddb) {
        Map<String, AttributeValue> item = new HashMap<String, AttributeValue>();

        item.put("doubleSet", b642Av("AE4AAAAFAAAAAi0zAAAABS0zNC4yAAAAATAAAAACMTUAAAADNy42"));
        item.put("*amzn-ddb-map-sig*", b642Av("AGIAAAAgm1KU7lGZlO6bNSxx1ZMr6pVmY1PuYw8uDIcFDisFjSw="));
        item.put("hashKey", b642Av("AG4AAAABMA=="));
        item.put("*amzn-ddb-map-desc*", b642Av("AGIAAAAyAAAAAAAAABVhbXpuLWRkYi1tYXAtc3ltLW1vZGUAAAARL0NCQy9QS0NTNVBhZGRpbmc="));
        item.put("intSet", b642Av("AGIAAAAwvTohJVr6lrUAhSuZT7nPaxgL6iW+IC0TZA1/ht30GWig2OO7JQFIS4O6Kk2ANI6w"));
        item.put("stringValue", b642Av("AHMAAAAHQmxhcmdoIQ=="));
        item.put("doubleValue", b642Av("AG4AAAACMTU="));
        item.put("rangeKey", b642Av("AG4AAAACMTU="));
        item.put("intValue", b642Av("AG4AAAABMA=="));
        item.put("version", b642Av("AG4AAAABMQ=="));
        ddb.putItem(new PutItemRequest("TableName", item));
        item.clear();

        item.put("doubleSet", b642Av("AE4AAAAFAAAAAi0zAAAABS0zNC4yAAAAATAAAAACMTUAAAADNy42"));
        item.put("*amzn-ddb-map-sig*", b642Av("AGIAAAAgm1KU7lGZlO6bNSxx1ZMr6pVmY1PuYw8uDIcFDisFjSw="));
        item.put("hashKey", b642Av("AG4AAAABMA=="));
        item.put("*amzn-ddb-map-desc*", b642Av("AGIAAAAyAAAAAAAAABVhbXpuLWRkYi1tYXAtc3ltLW1vZGUAAAARL0NCQy9QS0NTNVBhZGRpbmc="));
        item.put("intSet", b642Av("AGIAAAAwvTohJVr6lrUAhSuZT7nPaxgL6iW+IC0TZA1/ht30GWig2OO7JQFIS4O6Kk2ANI6w"));
        item.put("stringValue", b642Av("AHMAAAAHQmxhcmdoIQ=="));
        item.put("doubleValue", b642Av("AG4AAAACMTU="));
        item.put("rangeKey", b642Av("AG4AAAACMTU="));
        item.put("intValue", b642Av("AG4AAAABMA=="));
        item.put("version", b642Av("AG4AAAABMQ=="));
        ddb.putItem(new PutItemRequest("TableName", item));
        item.clear();

        item.put("*amzn-ddb-map-sig*", b642Av("AGIAAAAgiZXCp3s7VEMYdf01YEWqMlXOBHv3+e8gKbECrPUW47I="));
        item.put("hashKey", b642Av("AHMAAAADQmFy"));
        item.put("*amzn-ddb-map-desc*", b642Av("AGIAAAAyAAAAAAAAABVhbXpuLWRkYi1tYXAtc3ltLW1vZGUAAAARL0NCQy9QS0NTNVBhZGRpbmc="));
        ddb.putItem(new PutItemRequest("HashKeyOnly", item));
        item.clear();

        item.put("*amzn-ddb-map-sig*", b642Av("AGIAAAAgzh74eH/yJQFzkm5mq52iFAlSDpXAFe3ZP2nv7X/xY1w="));
        item.put("hashKey", b642Av("AHMAAAADQmF6"));
        item.put("*amzn-ddb-map-desc*", b642Av("AGIAAAAyAAAAAAAAABVhbXpuLWRkYi1tYXAtc3ltLW1vZGUAAAARL0NCQy9QS0NTNVBhZGRpbmc="));
        ddb.putItem(new PutItemRequest("HashKeyOnly", item));
        item.clear();

        item.put("*amzn-ddb-map-sig*", b642Av("AGIAAAAgHR5P6kozMSqqs+rnDMaCiymH8++OwEVzx2Y13ZMp5P8="));
        item.put("hashKey", b642Av("AHMAAAADRm9v"));
        item.put("*amzn-ddb-map-desc*", b642Av("AGIAAAAyAAAAAAAAABVhbXpuLWRkYi1tYXAtc3ltLW1vZGUAAAARL0NCQy9QS0NTNVBhZGRpbmc="));
        ddb.putItem(new PutItemRequest("HashKeyOnly", item));
        item.clear();

        item.put("*amzn-ddb-map-sig*", b642Av("AGIAAAAglBLoUXuc8TgsJJlItgBh6PJ1YVk52nvQE9aErEB8jK8="));
        item.put("hashKey", b642Av("AG4AAAABMA=="));
        item.put("*amzn-ddb-map-desc*", b642Av("AGIAAAAyAAAAAAAAABVhbXpuLWRkYi1tYXAtc3ltLW1vZGUAAAARL0NCQy9QS0NTNVBhZGRpbmc="));
        item.put("rangeKey", b642Av("AG4AAAABMQ=="));
        ddb.putItem(new PutItemRequest("TableName", item));
        item.clear();

        item.put("*amzn-ddb-map-sig*", b642Av("AGIAAAAgcjd91WBBFWPnrJxIJ2p2hnXFVCemgYw0HqRWcnoQcq4="));
        item.put("hashKey", b642Av("AG4AAAABMA=="));
        item.put("*amzn-ddb-map-desc*", b642Av("AGIAAAAyAAAAAAAAABVhbXpuLWRkYi1tYXAtc3ltLW1vZGUAAAARL0NCQy9QS0NTNVBhZGRpbmc="));
        item.put("rangeKey", b642Av("AG4AAAABMg=="));
        ddb.putItem(new PutItemRequest("TableName", item));
        item.clear();

        item.put("*amzn-ddb-map-sig*", b642Av("AGIAAAAguXZKvYmUgZEOunUJctXpkvqhrgUoK1eLi8JpvlRozTI="));
        item.put("hashKey", b642Av("AG4AAAABMA=="));
        item.put("*amzn-ddb-map-desc*", b642Av("AGIAAAAyAAAAAAAAABVhbXpuLWRkYi1tYXAtc3ltLW1vZGUAAAARL0NCQy9QS0NTNVBhZGRpbmc="));
        item.put("rangeKey", b642Av("AG4AAAABMw=="));
        ddb.putItem(new PutItemRequest("TableName", item));
        item.clear();

        item.put("*amzn-ddb-map-sig*", b642Av("AGIAAAAgyT2ehLcx/a609Ez6laLkTAqCtp0IYzzKV8Amv8jdQMw="));
        item.put("hashKey", b642Av("AG4AAAABMQ=="));
        item.put("*amzn-ddb-map-desc*", b642Av("AGIAAAAyAAAAAAAAABVhbXpuLWRkYi1tYXAtc3ltLW1vZGUAAAARL0NCQy9QS0NTNVBhZGRpbmc="));
        item.put("rangeKey", b642Av("AG4AAAABMQ=="));
        ddb.putItem(new PutItemRequest("TableName", item));
        item.clear();

        item.put("*amzn-ddb-map-sig*", b642Av("AGIAAAAgYAai32/7MVrGjSzgcVxkFDqU+G9HcmuiNSWZHcnvfjg="));
        item.put("hashKey", b642Av("AG4AAAABMQ=="));
        item.put("*amzn-ddb-map-desc*", b642Av("AGIAAAAyAAAAAAAAABVhbXpuLWRkYi1tYXAtc3ltLW1vZGUAAAARL0NCQy9QS0NTNVBhZGRpbmc="));
        item.put("rangeKey", b642Av("AG4AAAABMg=="));
        ddb.putItem(new PutItemRequest("TableName", item));
        item.clear();

        item.put("*amzn-ddb-map-sig*", b642Av("AGIAAAAg0iwjbBLCdtSosmDTDYzKxu3Q5qda0Ok9q3VbIJczBV0="));
        item.put("hashKey", b642Av("AG4AAAABMQ=="));
        item.put("*amzn-ddb-map-desc*", b642Av("AGIAAAAyAAAAAAAAABVhbXpuLWRkYi1tYXAtc3ltLW1vZGUAAAARL0NCQy9QS0NTNVBhZGRpbmc="));
        item.put("rangeKey", b642Av("AG4AAAABMw=="));
        ddb.putItem(new PutItemRequest("TableName", item));
        item.clear();

        item.put("*amzn-ddb-map-sig*", b642Av("AGIAAAAgGl1jMNLZl/B70Hz2B4K4K46kir+hE6AeX8azZfFi8GA="));
        item.put("hashKey", b642Av("AG4AAAABNQ=="));
        item.put("*amzn-ddb-map-desc*", b642Av("AGIAAAAyAAAAAAAAABVhbXpuLWRkYi1tYXAtc3ltLW1vZGUAAAARL0NCQy9QS0NTNVBhZGRpbmc="));
        item.put("rangeKey", b642Av("AG4AAAABMQ=="));
        ddb.putItem(new PutItemRequest("TableName", item));
        item.clear();

        item.put("doubleSet", b642Av("AGIAAABAbu/qi2UnCw6Saur96Xjc+1sQQzo6ZUdeu9W0/uX958B9utw+rDlclexaDcf6VGnz7OYM18eeEXrpjIgLtH4iaQ=="));
        item.put("*amzn-ddb-map-sig*", b642Av("AGIAAAAgfqIf7vj1G3qbcEv1nbyTqNoKSAFfj9fLMb3S8YEFjfM="));
        item.put("hashKey", b642Av("AG4AAAABNQ=="));
        item.put("*amzn-ddb-map-desc*", b642Av("AGIAAAAyAAAAAAAAABVhbXpuLWRkYi1tYXAtc3ltLW1vZGUAAAARL0NCQy9QS0NTNVBhZGRpbmc="));
        item.put("intSet", b642Av("AGIAAABAj0vcD4vvFrL/7JHHgnyBCIHb5u/WvT/Uc/kk4lBMFKV2NXshqqEmBu8UK96OLbYAK3+vW4mwm4rIZ7MqgV95LQ=="));
        item.put("stringValue", b642Av("AGIAAAAwyV633bs6t+yjSw6vHtUgrpDNB5YyMgXue0prPMXVm6SmGiUxS5l93cJx4vPWF/bi"));
        item.put("doubleValue", b642Av("AGIAAAAgBhZIjFx+b3DExrUfnOkJjYNw0/Bw+KoDxG4LUyzQoRA="));
        item.put("stringSet", b642Av("AGIAAABAWsWFF2IDOEl0f4PlW73arTFdMCyS6lMbvnrH9sPnCCMCQzEaSmdZmz1Kcb3ZDxRiaeLLWV2om/J9b260y2igRg=="));
        item.put("rangeKey", b642Av("AG4AAAABNw=="));
        item.put("byteArrayValue", b642Av("AGIAAAAgLB7p2Ewobv+WsSeh1KxHx0Gkw0e1sKTbZBfjkvoEZBs="));
        item.put("intValue", b642Av("AGIAAAAgO8EY3/1vRX0odEkXQejXrUP24ToyD+4EHJ6TmKZVPkk="));
        item.put("version", b642Av("AG4AAAABMQ=="));
        ddb.putItem(new PutItemRequest("TableName", item));
        item.clear();

        item.put("*amzn-ddb-map-sig*", b642Av("AGIAAAAg66Vz0G8nOQzlvIpImXSkl+nmCpTYeRy8mAF4qgGgMw0="));
        item.put("hashKey", b642Av("AG4AAAABNg=="));
        item.put("*amzn-ddb-map-desc*", b642Av("AGIAAAAyAAAAAAAAABVhbXpuLWRkYi1tYXAtc3ltLW1vZGUAAAARL0NCQy9QS0NTNVBhZGRpbmc="));
        item.put("rangeKey", b642Av("AG4AAAABMg=="));
        ddb.putItem(new PutItemRequest("TableName", item));
        item.clear();

        item.put("doubleSet", b642Av("AE4AAAAFAAAAAi0zAAAABS0zNC4yAAAAATAAAAACMTUAAAADNy42"));
        item.put("*amzn-ddb-map-sig*", b642Av("AGIAAAAgQWOgS/Ba8ZZa9Y2l8DolewfyZosDKcLysahlumr0MVk="));
        item.put("hashKey", b642Av("AG4AAAABNg=="));
        item.put("*amzn-ddb-map-desc*", b642Av("AGIAAAAyAAAAAAAAABVhbXpuLWRkYi1tYXAtc3ltLW1vZGUAAAARL0NCQy9QS0NTNVBhZGRpbmc="));
        item.put("intSet", b642Av("AGIAAABAAtJqJj1aokidlC6qr8L3xZQNo7Yl2z8DsEXgJLRKnK73Oyg7jRDF0zjgp02qNae7mYNDkK2QeafeAexk8s7qdw=="));
        item.put("stringValue", b642Av("AHMAAAAMSGVsbG8gd29ybGQh"));
        item.put("doubleValue", b642Av("AG4AAAACMTU="));
        item.put("stringSet", b642Av("AGIAAABAnJNYeqOA5x3J3k3zO7CWUcbD1gU2xifPxQ4sraRhsnKyd+mE+ouhX2LpMwQ45nRXxV1nSeaN7MW+4vYn/sA/oQ=="));
        item.put("rangeKey", b642Av("AG4AAAABOA=="));
        item.put("byteArrayValue", b642Av("AGIAAAAg/icc0cvbG45rqCNdeMFJaklPx69nXo3/8XTE+vQafmI="));
        item.put("intValue", b642Av("AG4AAAADMTIz"));
        item.put("version", b642Av("AG4AAAABMQ=="));
        ddb.putItem(new PutItemRequest("TableName", item));
        item.clear();

        item.put("*amzn-ddb-map-sig*", b642Av("AGIAAAAgcSTe0npOBBtsxSN4F9mLF2WTyCN1+1owsVoGkYumiZQ="));
        item.put("hashKey", b642Av("AG4AAAABNw=="));
        item.put("*amzn-ddb-map-desc*", b642Av("AGIAAAAyAAAAAAAAABVhbXpuLWRkYi1tYXAtc3ltLW1vZGUAAAARL0NCQy9QS0NTNVBhZGRpbmc="));
        item.put("rangeKey", b642Av("AG4AAAABMw=="));
        ddb.putItem(new PutItemRequest("TableName", item));
        item.clear();

        item.put("doubleSet", b642Av("AE4AAAAFAAAAAi0zAAAABS0zNC4yAAAAATAAAAACMTUAAAADNy42"));
        item.put("hashKey", b642Av("AG4AAAABNw=="));
        item.put("intSet", b642Av("AE4AAAAFAAAAATAAAAABMQAAAAIxMAAAAAIxNQAAAAMyMDA="));
        item.put("stringValue", b642Av("AHMAAAAMSGVsbG8gd29ybGQh"));
        item.put("doubleValue", b642Av("AG4AAAACMTU="));
        item.put("rangeKey", b642Av("AG4AAAABOQ=="));
        item.put("stringSet", b642Av("AFMAAAAEAAAAAT8AAAAFQ3J1ZWwAAAAHR29vZGJ5ZQAAAAVXb3JsZA=="));
        item.put("byteArrayValue", b642Av("AGIAAAAGAAECAwQF"));
        item.put("intValue", b642Av("AG4AAAADMTIz"));
        item.put("version", b642Av("AG4AAAABMQ=="));
        ddb.putItem(new PutItemRequest("TableName", item));
        item.clear();

        item.put("doubleSet", b642Av("AE4AAAAFAAAAAi0zAAAABS0zNC4yAAAAATAAAAACMTUAAAADNy42"));
        item.put("*amzn-ddb-map-sig*", b642Av("AGIAAAAg5NHNzCBtZcVAUlz1ymLB7Ta+1n3VjffLj5WniFA9afo="));
        item.put("hashKey", b642Av("AG4AAAABOA=="));
        item.put("*amzn-ddb-map-desc*", b642Av("AGIAAAAyAAAAAAAAABVhbXpuLWRkYi1tYXAtc3ltLW1vZGUAAAARL0NCQy9QS0NTNVBhZGRpbmc="));
        item.put("intSet", b642Av("AE4AAAAFAAAAATAAAAABMQAAAAIxMAAAAAIxNQAAAAMyMDA="));
        item.put("stringValue", b642Av("AHMAAAAMSGVsbG8gd29ybGQh"));
        item.put("doubleValue", b642Av("AG4AAAACMTU="));
        item.put("stringSet", b642Av("AFMAAAAEAAAAAT8AAAAFQ3J1ZWwAAAAHR29vZGJ5ZQAAAAVXb3JsZA=="));
        item.put("rangeKey", b642Av("AG4AAAACMTA="));
        item.put("byteArrayValue", b642Av("AGIAAAAGAAECAwQF"));
        item.put("intValue", b642Av("AG4AAAADMTIz"));
        item.put("version", b642Av("AG4AAAABMQ=="));
        ddb.putItem(new PutItemRequest("TableName", item));
        item.clear();
    }

    private void insertV0FixedWrappingTransformSymWrappedData(final AmazonDynamoDB ddb) {
        Map<String, AttributeValue> item = new HashMap<String, AttributeValue>();
        item.put("hashKey", b642Av("AHMAAAADQmFy"));
        item.put("*amzn-ddb-map-desc*", b642Av("AGIAAAC9AAAAAAAAABBhbXpuLWRkYi1lbnYta2V5AAAAODNvNHkzTTB3UUFCRXl1UXN0SFVQUGF1NkpPMUhiNk1OWGxXQW5aWDhYdmFYTlUwNUluTFUxZz09AAAAEGFtem4tZGRiLWVudi1hbGcAAAADQUVTAAAAEWFtem4tZGRiLXdyYXAtYWxnAAAAB0FFU1dyYXAAAAAVYW16bi1kZGItbWFwLXN5bS1tb2RlAAAAES9DQkMvUEtDUzVQYWRkaW5n"));
        item.put("*amzn-ddb-map-sig*", b642Av("AGIAAAAgiZXCp3s7VEMYdf01YEWqMlXOBHv3+e8gKbECrPUW47I="));
        ddb.putItem(new PutItemRequest("HashKeyOnly", item));
        item.clear();

        item.put("hashKey", b642Av("AHMAAAADQmF6"));
        item.put("*amzn-ddb-map-desc*", b642Av("AGIAAAC9AAAAAAAAABBhbXpuLWRkYi1lbnYta2V5AAAAODlZdEVSWXVDT3A4MHlKVnJOYytYREFoaVN6UHdlRnNJQk1YRXMxSEQ2eGdvdmYveldabmMrQT09AAAAEGFtem4tZGRiLWVudi1hbGcAAAADQUVTAAAAEWFtem4tZGRiLXdyYXAtYWxnAAAAB0FFU1dyYXAAAAAVYW16bi1kZGItbWFwLXN5bS1tb2RlAAAAES9DQkMvUEtDUzVQYWRkaW5n"));
        item.put("*amzn-ddb-map-sig*", b642Av("AGIAAAAgzh74eH/yJQFzkm5mq52iFAlSDpXAFe3ZP2nv7X/xY1w="));
        ddb.putItem(new PutItemRequest("HashKeyOnly", item));
        item.clear();

        item.put("hashKey", b642Av("AHMAAAADRm9v"));
        item.put("*amzn-ddb-map-desc*", b642Av("AGIAAAC9AAAAAAAAABBhbXpuLWRkYi1lbnYta2V5AAAAOEw2YkExbWszYTZxek1YNUkyMkYyYzRvU0FmZ2VZdCtjQmtFYndDTzhYUzlkL0ZqV20wekpZUT09AAAAEGFtem4tZGRiLWVudi1hbGcAAAADQUVTAAAAEWFtem4tZGRiLXdyYXAtYWxnAAAAB0FFU1dyYXAAAAAVYW16bi1kZGItbWFwLXN5bS1tb2RlAAAAES9DQkMvUEtDUzVQYWRkaW5n"));
        item.put("*amzn-ddb-map-sig*", b642Av("AGIAAAAgHR5P6kozMSqqs+rnDMaCiymH8++OwEVzx2Y13ZMp5P8="));
        ddb.putItem(new PutItemRequest("HashKeyOnly", item));
        item.clear();

        item.put("rangeKey", b642Av("AG4AAAABMQ=="));
        item.put("hashKey", b642Av("AG4AAAABMQ=="));
        item.put("*amzn-ddb-map-desc*", b642Av("AGIAAAC9AAAAAAAAABBhbXpuLWRkYi1lbnYta2V5AAAAOEpKNDk2UGRpcDViOHlldTVxbEE0STNOUjFTVHdtZEd2REJwQWowNXprUmN0OFh6T3E1TmRJZz09AAAAEGFtem4tZGRiLWVudi1hbGcAAAADQUVTAAAAEWFtem4tZGRiLXdyYXAtYWxnAAAAB0FFU1dyYXAAAAAVYW16bi1kZGItbWFwLXN5bS1tb2RlAAAAES9DQkMvUEtDUzVQYWRkaW5n"));
        item.put("*amzn-ddb-map-sig*", b642Av("AGIAAAAgyT2ehLcx/a609Ez6laLkTAqCtp0IYzzKV8Amv8jdQMw="));
        ddb.putItem(new PutItemRequest("TableName", item));
        item.clear();

        item.put("rangeKey", b642Av("AG4AAAABMg=="));
        item.put("hashKey", b642Av("AG4AAAABMQ=="));
        item.put("*amzn-ddb-map-desc*", b642Av("AGIAAAC9AAAAAAAAABBhbXpuLWRkYi1lbnYta2V5AAAAOHNVQzNEekp5Tk1tZ3ZUSE1EVnh2Sng1OCtDT1h0UStwRzR4ZlVQL0pJTkRHOGI1M00wOFRBZz09AAAAEGFtem4tZGRiLWVudi1hbGcAAAADQUVTAAAAEWFtem4tZGRiLXdyYXAtYWxnAAAAB0FFU1dyYXAAAAAVYW16bi1kZGItbWFwLXN5bS1tb2RlAAAAES9DQkMvUEtDUzVQYWRkaW5n"));
        item.put("*amzn-ddb-map-sig*", b642Av("AGIAAAAgYAai32/7MVrGjSzgcVxkFDqU+G9HcmuiNSWZHcnvfjg="));
        ddb.putItem(new PutItemRequest("TableName", item));
        item.clear();

        item.put("rangeKey", b642Av("AG4AAAABMw=="));
        item.put("hashKey", b642Av("AG4AAAABMQ=="));
        item.put("*amzn-ddb-map-desc*", b642Av("AGIAAAC9AAAAAAAAABBhbXpuLWRkYi1lbnYta2V5AAAAOEZGdjVQNjAxZzF0eXhoaDhxQmlCdDB1d2JoODlRaDdyeTcxL2lJdWxvSWNvQzFBV3JHczhtdz09AAAAEGFtem4tZGRiLWVudi1hbGcAAAADQUVTAAAAEWFtem4tZGRiLXdyYXAtYWxnAAAAB0FFU1dyYXAAAAAVYW16bi1kZGItbWFwLXN5bS1tb2RlAAAAES9DQkMvUEtDUzVQYWRkaW5n"));
        item.put("*amzn-ddb-map-sig*", b642Av("AGIAAAAg0iwjbBLCdtSosmDTDYzKxu3Q5qda0Ok9q3VbIJczBV0="));
        ddb.putItem(new PutItemRequest("TableName", item));
        item.clear();

        item.put("rangeKey", b642Av("AG4AAAABMQ=="));
        item.put("hashKey", b642Av("AG4AAAABNQ=="));
        item.put("*amzn-ddb-map-desc*", b642Av("AGIAAAC9AAAAAAAAABBhbXpuLWRkYi1lbnYta2V5AAAAOHJ3OU5qdU53dkhENTZPTmlqWC9nbUlGZ051ZDk3OS94QXhlaTVjbmdJbmxhajdpSVg0RDdadz09AAAAEGFtem4tZGRiLWVudi1hbGcAAAADQUVTAAAAEWFtem4tZGRiLXdyYXAtYWxnAAAAB0FFU1dyYXAAAAAVYW16bi1kZGItbWFwLXN5bS1tb2RlAAAAES9DQkMvUEtDUzVQYWRkaW5n"));
        item.put("*amzn-ddb-map-sig*", b642Av("AGIAAAAgGl1jMNLZl/B70Hz2B4K4K46kir+hE6AeX8azZfFi8GA="));
        ddb.putItem(new PutItemRequest("TableName", item));
        item.clear();

        item.put("rangeKey", b642Av("AG4AAAABNw=="));
        item.put("hashKey", b642Av("AG4AAAABNQ=="));
        item.put("stringValue", b642Av("AGIAAAAwMyVrAzOuKFS+hAiVq0jlmIJcwMP2w62LdWChncBN0q0HMB3WpADYK2BF1q+oQP83"));
        item.put("*amzn-ddb-map-desc*", b642Av("AGIAAAC9AAAAAAAAABBhbXpuLWRkYi1lbnYta2V5AAAAOHlUK09JWlpaWkE5VmU0dTdwRE1zNG9TUVZTNlFYZEFmQjZkVjlMMUg4QzBrRXliQ0Nad0JRQT09AAAAEGFtem4tZGRiLWVudi1hbGcAAAADQUVTAAAAEWFtem4tZGRiLXdyYXAtYWxnAAAAB0FFU1dyYXAAAAAVYW16bi1kZGItbWFwLXN5bS1tb2RlAAAAES9DQkMvUEtDUzVQYWRkaW5n"));
        item.put("intSet", b642Av("AGIAAABA0iLxGtvyDaUNXY1iYwcDlZX3zIs+QOMsBQ+RbX6YlAgFdMK/k57OXPH3jMIptzkNAKNWFea+NAz+AXFd2jPC8w=="));
        item.put("doubleSet", b642Av("AGIAAABA0nazy+tnY85GZpSANJzBLXZHPKzCvN4ggpopjujfAOO37wDi6zrSwhurLpjFIJGR27pn5azaroZWYA8GLfiGIw=="));
        item.put("byteArrayValue", b642Av("AGIAAAAgw9sfXioZCE9luCt4qiOixyRJVlJ6zbTwFoFg0wQNJbA="));
        item.put("stringSet", b642Av("AGIAAABA8057NGIAJADqX/KzkjZl7XzFMI/6j7vAbp5F83tZjOQhguhp8hheXAzcsrCmM6sME1oGEmJEran4Svs1qT5ChA=="));
        item.put("intValue", b642Av("AGIAAAAgLFHv7oLor2SoKypi/gubI0IsipoLd/I20qPr2wHOgOs="));
        item.put("doubleValue", b642Av("AGIAAAAguq8MBbPKDskxhyJ6VCmd9EC6+tD3EuiqhgFUpxckzdk="));
        item.put("version", b642Av("AG4AAAABMQ=="));
        item.put("*amzn-ddb-map-sig*", b642Av("AGIAAAAgFhpaX3jXqz+Pg4QETqcNBULC+OBOTkux2BFGCdnr5PY="));
        ddb.putItem(new PutItemRequest("TableName", item));
        item.clear();

        item.put("rangeKey", b642Av("AG4AAAACMTA="));
        item.put("hashKey", b642Av("AG4AAAABOA=="));
        item.put("stringValue", b642Av("AHMAAAAMSGVsbG8gd29ybGQh"));
        item.put("*amzn-ddb-map-desc*", b642Av("AGIAAAC9AAAAAAAAABBhbXpuLWRkYi1lbnYta2V5AAAAODRhOGRFc01ybDR6ODlVM1RkOWh4L0J2cms4cVZEODlOaklkMnU0d2NGSnBxbUVkc1lka2ZXZz09AAAAEGFtem4tZGRiLWVudi1hbGcAAAADQUVTAAAAEWFtem4tZGRiLXdyYXAtYWxnAAAAB0FFU1dyYXAAAAAVYW16bi1kZGItbWFwLXN5bS1tb2RlAAAAES9DQkMvUEtDUzVQYWRkaW5n"));
        item.put("intSet", b642Av("AE4AAAAFAAAAATAAAAABMQAAAAIxMAAAAAIxNQAAAAMyMDA="));
        item.put("doubleSet", b642Av("AE4AAAAFAAAAAi0zAAAABS0zNC4yAAAAATAAAAACMTUAAAADNy42"));
        item.put("byteArrayValue", b642Av("AGIAAAAGAAECAwQF"));
        item.put("stringSet", b642Av("AFMAAAAEAAAAAT8AAAAFQ3J1ZWwAAAAHR29vZGJ5ZQAAAAVXb3JsZA=="));
        item.put("intValue", b642Av("AG4AAAADMTIz"));
        item.put("doubleValue", b642Av("AG4AAAACMTU="));
        item.put("version", b642Av("AG4AAAABMQ=="));
        item.put("*amzn-ddb-map-sig*", b642Av("AGIAAAAg5NHNzCBtZcVAUlz1ymLB7Ta+1n3VjffLj5WniFA9afo="));
        ddb.putItem(new PutItemRequest("TableName", item));
        item.clear();

        item.put("rangeKey", b642Av("AG4AAAABMw=="));
        item.put("hashKey", b642Av("AG4AAAABNw=="));
        item.put("*amzn-ddb-map-desc*", b642Av("AGIAAAC9AAAAAAAAABBhbXpuLWRkYi1lbnYta2V5AAAAOE55eTdqK3FkNEJMNzV2MTlnRHdHVHdtTGgrbmlMaER0cjdaL3ZZMVFmQTFEQmE5Y0JGdzIxdz09AAAAEGFtem4tZGRiLWVudi1hbGcAAAADQUVTAAAAEWFtem4tZGRiLXdyYXAtYWxnAAAAB0FFU1dyYXAAAAAVYW16bi1kZGItbWFwLXN5bS1tb2RlAAAAES9DQkMvUEtDUzVQYWRkaW5n"));
        item.put("*amzn-ddb-map-sig*", b642Av("AGIAAAAgcSTe0npOBBtsxSN4F9mLF2WTyCN1+1owsVoGkYumiZQ="));
        ddb.putItem(new PutItemRequest("TableName", item));
        item.clear();

        item.put("rangeKey", b642Av("AG4AAAABOQ=="));
        item.put("hashKey", b642Av("AG4AAAABNw=="));
        item.put("stringValue", b642Av("AHMAAAAMSGVsbG8gd29ybGQh"));
        item.put("intSet", b642Av("AE4AAAAFAAAAATAAAAABMQAAAAIxMAAAAAIxNQAAAAMyMDA="));
        item.put("doubleSet", b642Av("AE4AAAAFAAAAAi0zAAAABS0zNC4yAAAAATAAAAACMTUAAAADNy42"));
        item.put("byteArrayValue", b642Av("AGIAAAAGAAECAwQF"));
        item.put("stringSet", b642Av("AFMAAAAEAAAAAT8AAAAFQ3J1ZWwAAAAHR29vZGJ5ZQAAAAVXb3JsZA=="));
        item.put("intValue", b642Av("AG4AAAADMTIz"));
        item.put("doubleValue", b642Av("AG4AAAACMTU="));
        item.put("version", b642Av("AG4AAAABMQ=="));
        ddb.putItem(new PutItemRequest("TableName", item));
        item.clear();

        item.put("rangeKey", b642Av("AG4AAAABMQ=="));
        item.put("hashKey", b642Av("AG4AAAABMA=="));
        item.put("*amzn-ddb-map-desc*", b642Av("AGIAAAC9AAAAAAAAABBhbXpuLWRkYi1lbnYta2V5AAAAOGcrY1NpV2I3eWZYZ2pQS2gzOVM0anBZZWFNeEhHRG90c2JCOG5sQkp3ei9vclBRQzhOZFNxdz09AAAAEGFtem4tZGRiLWVudi1hbGcAAAADQUVTAAAAEWFtem4tZGRiLXdyYXAtYWxnAAAAB0FFU1dyYXAAAAAVYW16bi1kZGItbWFwLXN5bS1tb2RlAAAAES9DQkMvUEtDUzVQYWRkaW5n"));
        item.put("*amzn-ddb-map-sig*", b642Av("AGIAAAAglBLoUXuc8TgsJJlItgBh6PJ1YVk52nvQE9aErEB8jK8="));
        ddb.putItem(new PutItemRequest("TableName", item));
        item.clear();

        item.put("rangeKey", b642Av("AG4AAAABMg=="));
        item.put("hashKey", b642Av("AG4AAAABMA=="));
        item.put("*amzn-ddb-map-desc*", b642Av("AGIAAAC9AAAAAAAAABBhbXpuLWRkYi1lbnYta2V5AAAAOHlKa2M4OW9HNEpoajhyazlEQnpVeEQ1cForN1Q4Z2pQUEU1TE9uVDhvd2tJWDJ6bGFpdUJKQT09AAAAEGFtem4tZGRiLWVudi1hbGcAAAADQUVTAAAAEWFtem4tZGRiLXdyYXAtYWxnAAAAB0FFU1dyYXAAAAAVYW16bi1kZGItbWFwLXN5bS1tb2RlAAAAES9DQkMvUEtDUzVQYWRkaW5n"));
        item.put("*amzn-ddb-map-sig*", b642Av("AGIAAAAgcjd91WBBFWPnrJxIJ2p2hnXFVCemgYw0HqRWcnoQcq4="));
        ddb.putItem(new PutItemRequest("TableName", item));
        item.clear();

        item.put("rangeKey", b642Av("AG4AAAABMw=="));
        item.put("hashKey", b642Av("AG4AAAABMA=="));
        item.put("*amzn-ddb-map-desc*", b642Av("AGIAAAC9AAAAAAAAABBhbXpuLWRkYi1lbnYta2V5AAAAOG9kQ2hPVmtiYkN3S3V3VHYrVjYvelNwcnZIUWVhWlpqaDZvU3JzMHV4T255bFQzSUZ0TjVVZz09AAAAEGFtem4tZGRiLWVudi1hbGcAAAADQUVTAAAAEWFtem4tZGRiLXdyYXAtYWxnAAAAB0FFU1dyYXAAAAAVYW16bi1kZGItbWFwLXN5bS1tb2RlAAAAES9DQkMvUEtDUzVQYWRkaW5n"));
        item.put("*amzn-ddb-map-sig*", b642Av("AGIAAAAguXZKvYmUgZEOunUJctXpkvqhrgUoK1eLi8JpvlRozTI="));
        ddb.putItem(new PutItemRequest("TableName", item));
        item.clear();

        item.put("rangeKey", b642Av("AG4AAAABMg=="));
        item.put("hashKey", b642Av("AG4AAAABNg=="));
        item.put("*amzn-ddb-map-desc*", b642Av("AGIAAAC9AAAAAAAAABBhbXpuLWRkYi1lbnYta2V5AAAAOEJLV0Z2T0hRVUxCMTcxTW56dkQrVVYyMVpmTUxhSXl4QjB3ekdZbStzY2VFd2pNekgxTFhVQT09AAAAEGFtem4tZGRiLWVudi1hbGcAAAADQUVTAAAAEWFtem4tZGRiLXdyYXAtYWxnAAAAB0FFU1dyYXAAAAAVYW16bi1kZGItbWFwLXN5bS1tb2RlAAAAES9DQkMvUEtDUzVQYWRkaW5n"));
        item.put("*amzn-ddb-map-sig*", b642Av("AGIAAAAg66Vz0G8nOQzlvIpImXSkl+nmCpTYeRy8mAF4qgGgMw0="));
        ddb.putItem(new PutItemRequest("TableName", item));
        item.clear();

        item.put("rangeKey", b642Av("AG4AAAABOA=="));
        item.put("stringValue", b642Av("AHMAAAAMSGVsbG8gd29ybGQh"));
        item.put("hashKey", b642Av("AG4AAAABNg=="));
        item.put("*amzn-ddb-map-desc*", b642Av("AGIAAAC9AAAAAAAAABBhbXpuLWRkYi1lbnYta2V5AAAAOEdncWp2Q3JaYzhZL2RrMGxmQlk5K09tbWNXUWIvbjVYMW01YTNBcElZb3JLVzU0RVhRYTgrZz09AAAAEGFtem4tZGRiLWVudi1hbGcAAAADQUVTAAAAEWFtem4tZGRiLXdyYXAtYWxnAAAAB0FFU1dyYXAAAAAVYW16bi1kZGItbWFwLXN5bS1tb2RlAAAAES9DQkMvUEtDUzVQYWRkaW5n"));
        item.put("doubleSet", b642Av("AE4AAAAFAAAAAi0zAAAABS0zNC4yAAAAATAAAAACMTUAAAADNy42"));
        item.put("intSet", b642Av("AGIAAABAeBhcgBr8TocxVsTw8tJtcAK2VKFOkoZlWBUusFNtKbTulghzdpT3iTMqIJB86ViXXguO43XqMZWs1U3G/IaF+g=="));
        item.put("byteArrayValue", b642Av("AGIAAAAgY3ciZfN54gf86a4mxRfon9CgzQkNIxrtWV8s6tg/6G0="));
        item.put("intValue", b642Av("AG4AAAADMTIz"));
        item.put("stringSet", b642Av("AGIAAABARhykbS8bqGEd2LEGtLV0S6Pj+4KjuVc15ExkUmlCKlClAgNpukA5Tp0FjU/XL0Qli4v6apZaraKgBC1l4YlRDg=="));
        item.put("doubleValue", b642Av("AG4AAAACMTU="));
        item.put("version", b642Av("AG4AAAABMQ=="));
        item.put("*amzn-ddb-map-sig*", b642Av("AGIAAAAgmC10Qiw1c/P8Bab4SaP3kmsPMBVfOZKjZ3SgvXyd3Vg="));
        ddb.putItem(new PutItemRequest("TableName", item));
        item.clear();
    }

    private void insertV0MetastoreData(AmazonDynamoDB ddb) {
        Map<String, AttributeValue> item = new HashMap<>();

        item.put("hashKey", b642Av("AHMAAAADQmFy"));
        item.put("*amzn-ddb-map-desc*", b642Av("AGIAAADjAAAAAAAAABBhbXpuLWRkYi1lbnYta2V5AAAAOGR5Y1YrQW42bUVFVzJLK3RjVE1EQWw2MUNRSzNPZ2hpQ2Z2YTBYeGFVaU9odWJnRDhMelFwdz09AAAAEGFtem4tZGRiLWVudi1hbGcAAAADQUVTAAAAEGFtem4tZGRiLW1ldGEtaWQAAAAObWF0ZXJpYWxOYW1lIzAAAAARYW16bi1kZGItd3JhcC1hbGcAAAAHQUVTV3JhcAAAABVhbXpuLWRkYi1tYXAtc3ltLW1vZGUAAAARL0NCQy9QS0NTNVBhZGRpbmc="));
        item.put("*amzn-ddb-map-sig*", b642Av("AGIAAAAgiBDp77rZmalAcIlg0htWCjJ0BcYgMdPgzJj8fie5Ai0="));
        ddb.putItem(new PutItemRequest("HashKeyOnly", item));
        item.clear();

        item.put("hashKey", b642Av("AHMAAAADQmF6"));
        item.put("*amzn-ddb-map-desc*", b642Av("AGIAAADjAAAAAAAAABBhbXpuLWRkYi1lbnYta2V5AAAAODlPZG50TUIwbHpoMUtKNHlYZXhrNXZsWVF4RUlWRDJZRWVybHlQNThXWkg1OUtxelM2MUIvdz09AAAAEGFtem4tZGRiLWVudi1hbGcAAAADQUVTAAAAEGFtem4tZGRiLW1ldGEtaWQAAAAObWF0ZXJpYWxOYW1lIzAAAAARYW16bi1kZGItd3JhcC1hbGcAAAAHQUVTV3JhcAAAABVhbXpuLWRkYi1tYXAtc3ltLW1vZGUAAAARL0NCQy9QS0NTNVBhZGRpbmc="));
        item.put("*amzn-ddb-map-sig*", b642Av("AGIAAAAgNo2a+yFlcr1phtcCGNXKfcUrfyMtPdihhh7UPWQNLog="));
        ddb.putItem(new PutItemRequest("HashKeyOnly", item));
        item.clear();

        item.put("hashKey", b642Av("AHMAAAADRm9v"));
        item.put("*amzn-ddb-map-desc*", b642Av("AGIAAADjAAAAAAAAABBhbXpuLWRkYi1lbnYta2V5AAAAOGtUMFY2bklwSHh2WTZ6bjMycHJHd0NJVFJRb1NyR3BsWGtoTlcxdUJZWnA2QVFUSURiT3dVUT09AAAAEGFtem4tZGRiLWVudi1hbGcAAAADQUVTAAAAEGFtem4tZGRiLW1ldGEtaWQAAAAObWF0ZXJpYWxOYW1lIzAAAAARYW16bi1kZGItd3JhcC1hbGcAAAAHQUVTV3JhcAAAABVhbXpuLWRkYi1tYXAtc3ltLW1vZGUAAAARL0NCQy9QS0NTNVBhZGRpbmc="));
        item.put("*amzn-ddb-map-sig*", b642Av("AGIAAAAgfy9BE3X7MyBJCQLvCN8TNUTf/zJvKEQQOdf9VhJbWdU="));
        ddb.putItem(new PutItemRequest("HashKeyOnly", item));
        item.clear();

        item.put("rangeKey", b642Av("AG4AAAABMQ=="));
        item.put("hashKey", b642Av("AG4AAAABMQ=="));
        item.put("*amzn-ddb-map-desc*", b642Av("AGIAAADjAAAAAAAAABBhbXpuLWRkYi1lbnYta2V5AAAAODJLUkJKQlBxbEFEM0ZYL2RiSjhlRHFoL2NvdVZhUnJUZmpISE0rWFRtbS9xYThybHZ3Rkw1UT09AAAAEGFtem4tZGRiLWVudi1hbGcAAAADQUVTAAAAEGFtem4tZGRiLW1ldGEtaWQAAAAObWF0ZXJpYWxOYW1lIzAAAAARYW16bi1kZGItd3JhcC1hbGcAAAAHQUVTV3JhcAAAABVhbXpuLWRkYi1tYXAtc3ltLW1vZGUAAAARL0NCQy9QS0NTNVBhZGRpbmc="));
        item.put("*amzn-ddb-map-sig*", b642Av("AGIAAAAgQv9omCLGhrq2cxeP+elq4UgbloK03bV+knv8uE9P7Mw="));
        ddb.putItem(new PutItemRequest("TableName", item));
        item.clear();

        item.put("rangeKey", b642Av("AG4AAAABMg=="));
        item.put("hashKey", b642Av("AG4AAAABMQ=="));
        item.put("*amzn-ddb-map-desc*", b642Av("AGIAAADjAAAAAAAAABBhbXpuLWRkYi1lbnYta2V5AAAAOHZyckFUOHhzOTJJNlpMdVFtcGs2SDR2RTJ6WlljMVRjZkNXb2VUVXdPcVN3K29Gb0JTWFlQUT09AAAAEGFtem4tZGRiLWVudi1hbGcAAAADQUVTAAAAEGFtem4tZGRiLW1ldGEtaWQAAAAObWF0ZXJpYWxOYW1lIzAAAAARYW16bi1kZGItd3JhcC1hbGcAAAAHQUVTV3JhcAAAABVhbXpuLWRkYi1tYXAtc3ltLW1vZGUAAAARL0NCQy9QS0NTNVBhZGRpbmc="));
        item.put("*amzn-ddb-map-sig*", b642Av("AGIAAAAgtgkdLHwtDS/NzFDFLQR8GQLsw4LURQMB/8yBoD4kKSI="));
        ddb.putItem(new PutItemRequest("TableName", item));
        item.clear();

        item.put("rangeKey", b642Av("AG4AAAABMw=="));
        item.put("hashKey", b642Av("AG4AAAABMQ=="));
        item.put("*amzn-ddb-map-desc*", b642Av("AGIAAADjAAAAAAAAABBhbXpuLWRkYi1lbnYta2V5AAAAOENTT0dQcXZZM0d5QUJSZTB1MXVTLzR4ZGtQRlRSQlh0M3dkSGJ2bXoveUNCcEk3bGY3Qit1dz09AAAAEGFtem4tZGRiLWVudi1hbGcAAAADQUVTAAAAEGFtem4tZGRiLW1ldGEtaWQAAAAObWF0ZXJpYWxOYW1lIzAAAAARYW16bi1kZGItd3JhcC1hbGcAAAAHQUVTV3JhcAAAABVhbXpuLWRkYi1tYXAtc3ltLW1vZGUAAAARL0NCQy9QS0NTNVBhZGRpbmc="));
        item.put("*amzn-ddb-map-sig*", b642Av("AGIAAAAgUPLAdN9KAJNJRZzAtfpaloOYNa+gCVXg1diT6CGSqrU="));
        ddb.putItem(new PutItemRequest("TableName", item));
        item.clear();

        item.put("rangeKey", b642Av("AG4AAAABMQ=="));
        item.put("hashKey", b642Av("AG4AAAABNQ=="));
        item.put("*amzn-ddb-map-desc*", b642Av("AGIAAADjAAAAAAAAABBhbXpuLWRkYi1lbnYta2V5AAAAOG1WcldlSy9CYkxsSDlnY0Zvb1Fjb0I4V082anlSa0hRT2NqN0NaZjFzMUk0RWRuV0NGai9CQT09AAAAEGFtem4tZGRiLWVudi1hbGcAAAADQUVTAAAAEGFtem4tZGRiLW1ldGEtaWQAAAAObWF0ZXJpYWxOYW1lIzAAAAARYW16bi1kZGItd3JhcC1hbGcAAAAHQUVTV3JhcAAAABVhbXpuLWRkYi1tYXAtc3ltLW1vZGUAAAARL0NCQy9QS0NTNVBhZGRpbmc="));
        item.put("*amzn-ddb-map-sig*", b642Av("AGIAAAAgDY8cXYd+66/OeHT+dOOh4FnJgwD4mMj/0EOZZdlrDGU="));
        ddb.putItem(new PutItemRequest("TableName", item));
        item.clear();

        item.put("rangeKey", b642Av("AG4AAAABNw=="));
        item.put("stringValue", b642Av("AGIAAAAwjmiBDtOhOzwPbKbPx15zZ+HeW0ElgRnRiGykEvmvpFux0U/LJQFRQ9KncAWd4nJM"));
        item.put("hashKey", b642Av("AG4AAAABNQ=="));
        item.put("*amzn-ddb-map-desc*", b642Av("AGIAAADjAAAAAAAAABBhbXpuLWRkYi1lbnYta2V5AAAAOGNaYlhrb0ZDLzZjVzlpNWNBanViTHdZaW1vNE9SdlUxQjZOSWRpRHovc1BsMUQwU1F2ajhWQT09AAAAEGFtem4tZGRiLWVudi1hbGcAAAADQUVTAAAAEGFtem4tZGRiLW1ldGEtaWQAAAAObWF0ZXJpYWxOYW1lIzAAAAARYW16bi1kZGItd3JhcC1hbGcAAAAHQUVTV3JhcAAAABVhbXpuLWRkYi1tYXAtc3ltLW1vZGUAAAARL0NCQy9QS0NTNVBhZGRpbmc="));
        item.put("doubleSet", b642Av("AGIAAABAS4kDtlVOu6tLMGoBhqD8oDGY8WnnUnZ6gN2E0TLmTn6+rJeFBQ3R0NfJtsXtx8pKKOZRG7z5nkJqVCXWA0YEtg=="));
        item.put("intSet", b642Av("AGIAAABAuU3x6fQO9kF37qXb+KdB50EvDsAQSr7JEkKFo76XSF3q1jRNuXTvNL1MmCagMicOn8hGXWf3uXr3l/jeMXXTxw=="));
        item.put("byteArrayValue", b642Av("AGIAAAAg1v7mQNUIJrvRrBqSBP8Ges17M8ylNfERqjAhpBtmtEg="));
        item.put("stringSet", b642Av("AGIAAABAMSooPgKThBmQfGl+MZ0PcPhwCWpykLn5VIYK8y17sa7S9HPC+ZZaXSZWAeEIe9tCsazs/GhYPNAk+J9+Ehr83A=="));
        item.put("intValue", b642Av("AGIAAAAgFLAPKKtgQS0xyDmVtg8TM8NsK5Zt7HSPorfyxIzw920="));
        item.put("doubleValue", b642Av("AGIAAAAgIKFrRJV/QQ6bN880QRBKXR/K84kwc5O8cAFduodO5dU="));
        item.put("version", b642Av("AG4AAAABMQ=="));
        item.put("*amzn-ddb-map-sig*", b642Av("AGIAAAAgzZEKidI2XCh5bvadadW99btbRcOVSuavthxLMEIN86c="));
        ddb.putItem(new PutItemRequest("TableName", item));
        item.clear();

        item.put("rangeKey", b642Av("AG4AAAACMTA="));
        item.put("stringValue", b642Av("AHMAAAAMSGVsbG8gd29ybGQh"));
        item.put("hashKey", b642Av("AG4AAAABOA=="));
        item.put("*amzn-ddb-map-desc*", b642Av("AGIAAADjAAAAAAAAABBhbXpuLWRkYi1lbnYta2V5AAAAODlqNDlhRG51M1hBNVE0M0xxMDMvaTF3eUIzbHdSbng4eDNEK29JamM3Qlpxbno5VmhoRHc2Zz09AAAAEGFtem4tZGRiLWVudi1hbGcAAAADQUVTAAAAEGFtem4tZGRiLW1ldGEtaWQAAAAObWF0ZXJpYWxOYW1lIzAAAAARYW16bi1kZGItd3JhcC1hbGcAAAAHQUVTV3JhcAAAABVhbXpuLWRkYi1tYXAtc3ltLW1vZGUAAAARL0NCQy9QS0NTNVBhZGRpbmc="));
        item.put("doubleSet", b642Av("AE4AAAAFAAAAAi0zAAAABS0zNC4yAAAAATAAAAACMTUAAAADNy42"));
        item.put("intSet", b642Av("AE4AAAAFAAAAATAAAAABMQAAAAIxMAAAAAIxNQAAAAMyMDA="));
        item.put("byteArrayValue", b642Av("AGIAAAAGAAECAwQF"));
        item.put("stringSet", b642Av("AFMAAAAEAAAAAT8AAAAFQ3J1ZWwAAAAHR29vZGJ5ZQAAAAVXb3JsZA=="));
        item.put("intValue", b642Av("AG4AAAADMTIz"));
        item.put("doubleValue", b642Av("AG4AAAACMTU="));
        item.put("version", b642Av("AG4AAAABMQ=="));
        item.put("*amzn-ddb-map-sig*", b642Av("AGIAAAAgTUBX7q3xvSd+K/nMBdipsX+6nTyt+htT/qJUK5sPos0="));
        ddb.putItem(new PutItemRequest("TableName", item));
        item.clear();

        item.put("rangeKey", b642Av("AG4AAAABMw=="));
        item.put("hashKey", b642Av("AG4AAAABNw=="));
        item.put("*amzn-ddb-map-desc*", b642Av("AGIAAADjAAAAAAAAABBhbXpuLWRkYi1lbnYta2V5AAAAOHA3N1pGSEh5Wk5qZXErWDdHdHhsRkNzZDVqemhTSFVQVFc1V3YzU0xPaHFFdzQzUmJEdUVOUT09AAAAEGFtem4tZGRiLWVudi1hbGcAAAADQUVTAAAAEGFtem4tZGRiLW1ldGEtaWQAAAAObWF0ZXJpYWxOYW1lIzAAAAARYW16bi1kZGItd3JhcC1hbGcAAAAHQUVTV3JhcAAAABVhbXpuLWRkYi1tYXAtc3ltLW1vZGUAAAARL0NCQy9QS0NTNVBhZGRpbmc="));
        item.put("*amzn-ddb-map-sig*", b642Av("AGIAAAAgc4AE+L/ysYL+maoJmXJkaMeJ3Chh1Ed8KQA148yZK6M="));
        ddb.putItem(new PutItemRequest("TableName", item));
        item.clear();

        item.put("rangeKey", b642Av("AG4AAAABOQ=="));
        item.put("stringValue", b642Av("AHMAAAAMSGVsbG8gd29ybGQh"));
        item.put("hashKey", b642Av("AG4AAAABNw=="));
        item.put("doubleSet", b642Av("AE4AAAAFAAAAAi0zAAAABS0zNC4yAAAAATAAAAACMTUAAAADNy42"));
        item.put("intSet", b642Av("AE4AAAAFAAAAATAAAAABMQAAAAIxMAAAAAIxNQAAAAMyMDA="));
        item.put("byteArrayValue", b642Av("AGIAAAAGAAECAwQF"));
        item.put("stringSet", b642Av("AFMAAAAEAAAAAT8AAAAFQ3J1ZWwAAAAHR29vZGJ5ZQAAAAVXb3JsZA=="));
        item.put("intValue", b642Av("AG4AAAADMTIz"));
        item.put("doubleValue", b642Av("AG4AAAACMTU="));
        item.put("version", b642Av("AG4AAAABMQ=="));
        ddb.putItem(new PutItemRequest("TableName", item));
        item.clear();

        item.put("rangeKey", b642Av("AG4AAAABMQ=="));
        item.put("hashKey", b642Av("AG4AAAABMA=="));
        item.put("*amzn-ddb-map-desc*", b642Av("AGIAAADjAAAAAAAAABBhbXpuLWRkYi1lbnYta2V5AAAAOFI3eGxEWmZCTTRoMWhaa0EreldTQ0VNV3ZCVnV2Vm03Z25wVnlmTVBRMW5hYi9KQWhiRUs3UT09AAAAEGFtem4tZGRiLWVudi1hbGcAAAADQUVTAAAAEGFtem4tZGRiLW1ldGEtaWQAAAAObWF0ZXJpYWxOYW1lIzAAAAARYW16bi1kZGItd3JhcC1hbGcAAAAHQUVTV3JhcAAAABVhbXpuLWRkYi1tYXAtc3ltLW1vZGUAAAARL0NCQy9QS0NTNVBhZGRpbmc="));
        item.put("*amzn-ddb-map-sig*", b642Av("AGIAAAAgRU3MCwYYxRFxZT7GmHBG7j+pgK14aMfEIsmrbgB8+Wk="));
        ddb.putItem(new PutItemRequest("TableName", item));
        item.clear();

        item.put("rangeKey", b642Av("AG4AAAABMg=="));
        item.put("hashKey", b642Av("AG4AAAABMA=="));
        item.put("*amzn-ddb-map-desc*", b642Av("AGIAAADjAAAAAAAAABBhbXpuLWRkYi1lbnYta2V5AAAAOGkxcGFYZUtNRXlTTDFDOUdwaS9QWFVDMk15ZHdUeUxKTGQ3RXNIeWUrazJrRWlxTnBRdFZnZz09AAAAEGFtem4tZGRiLWVudi1hbGcAAAADQUVTAAAAEGFtem4tZGRiLW1ldGEtaWQAAAAObWF0ZXJpYWxOYW1lIzAAAAARYW16bi1kZGItd3JhcC1hbGcAAAAHQUVTV3JhcAAAABVhbXpuLWRkYi1tYXAtc3ltLW1vZGUAAAARL0NCQy9QS0NTNVBhZGRpbmc="));
        item.put("*amzn-ddb-map-sig*", b642Av("AGIAAAAg5gNtdXLSncuZDK3EvpFos08QRhOsOnKDVNR9jogw/Bk="));
        ddb.putItem(new PutItemRequest("TableName", item));
        item.clear();

        item.put("rangeKey", b642Av("AG4AAAABMw=="));
        item.put("hashKey", b642Av("AG4AAAABMA=="));
        item.put("*amzn-ddb-map-desc*", b642Av("AGIAAADjAAAAAAAAABBhbXpuLWRkYi1lbnYta2V5AAAAOGxCdUFkQ0pYSk9yVS9JelM4TEV1RlFoWDhnVVVCMG5jZDNxZ0FUQ0xjMjVrYTE0RFRTVjNKQT09AAAAEGFtem4tZGRiLWVudi1hbGcAAAADQUVTAAAAEGFtem4tZGRiLW1ldGEtaWQAAAAObWF0ZXJpYWxOYW1lIzAAAAARYW16bi1kZGItd3JhcC1hbGcAAAAHQUVTV3JhcAAAABVhbXpuLWRkYi1tYXAtc3ltLW1vZGUAAAARL0NCQy9QS0NTNVBhZGRpbmc="));
        item.put("*amzn-ddb-map-sig*", b642Av("AGIAAAAg6zpNDAHNoQUzrP6YE6g47Y7CDom04EWXUTGuhPU7Wd8="));
        ddb.putItem(new PutItemRequest("TableName", item));
        item.clear();

        item.put("rangeKey", b642Av("AG4AAAABMg=="));
        item.put("hashKey", b642Av("AG4AAAABNg=="));
        item.put("*amzn-ddb-map-desc*", b642Av("AGIAAADjAAAAAAAAABBhbXpuLWRkYi1lbnYta2V5AAAAOFdsRU5LNlNmY096R3owYTRwL2RyRHF5REo4LzJ0REJ0WTRRL0wxdUpRc1lYeldRQ2pUcExkQT09AAAAEGFtem4tZGRiLWVudi1hbGcAAAADQUVTAAAAEGFtem4tZGRiLW1ldGEtaWQAAAAObWF0ZXJpYWxOYW1lIzAAAAARYW16bi1kZGItd3JhcC1hbGcAAAAHQUVTV3JhcAAAABVhbXpuLWRkYi1tYXAtc3ltLW1vZGUAAAARL0NCQy9QS0NTNVBhZGRpbmc="));
        item.put("*amzn-ddb-map-sig*", b642Av("AGIAAAAgtvX4UthmBwymnAZ7CuTpJdLTASr1lRj1MvRwAesjtMM="));
        ddb.putItem(new PutItemRequest("TableName", item));
        item.clear();

        item.put("rangeKey", b642Av("AG4AAAABOA=="));
        item.put("stringValue", b642Av("AHMAAAAMSGVsbG8gd29ybGQh"));
        item.put("hashKey", b642Av("AG4AAAABNg=="));
        item.put("*amzn-ddb-map-desc*", b642Av("AGIAAADjAAAAAAAAABBhbXpuLWRkYi1lbnYta2V5AAAAOGpyLzI2c1V1NW5udlQwcmVzY0NPWEhXTHZwZzlySjNkeURSVHQxRFFMcnAvTG9STkRyNk5EQT09AAAAEGFtem4tZGRiLWVudi1hbGcAAAADQUVTAAAAEGFtem4tZGRiLW1ldGEtaWQAAAAObWF0ZXJpYWxOYW1lIzAAAAARYW16bi1kZGItd3JhcC1hbGcAAAAHQUVTV3JhcAAAABVhbXpuLWRkYi1tYXAtc3ltLW1vZGUAAAARL0NCQy9QS0NTNVBhZGRpbmc="));
        item.put("doubleSet", b642Av("AE4AAAAFAAAAAi0zAAAABS0zNC4yAAAAATAAAAACMTUAAAADNy42"));
        item.put("intSet", b642Av("AGIAAABAUBGZEIoWzYKTFCsFoZYXzRUJsNuy3xr64nCwsL14lZNk62Aff5n3+ETtWm8U9E3PMOp9LozkDwZcnzs0rnYIeA=="));
        item.put("byteArrayValue", b642Av("AGIAAAAgl9wQf/r6vivuTCvIz0Jeqd80xPII30sf317fED7Xrrs="));
        item.put("intValue", b642Av("AG4AAAADMTIz"));
        item.put("stringSet", b642Av("AGIAAABAAijuavOYfNvcle2WbG8I2a4W1af+UPxhKguG3YMW5E6MoXsdO5ddSAifAPbVLmv92VyJnx/o817m1IOSs+LccA=="));
        item.put("doubleValue", b642Av("AG4AAAACMTU="));
        item.put("version", b642Av("AG4AAAABMQ=="));
        item.put("*amzn-ddb-map-sig*", b642Av("AGIAAAAgpzB3S616mcP6HQrkeaUYdV5Qo2UYWF6p04GZhSzcpV8="));
        ddb.putItem(new PutItemRequest("TableName", item));
        item.clear();

        item.put("*amzn-ddb-map-desc*", b642Av("AGIAAAAyAAAAAAAAABVhbXpuLWRkYi1tYXAtc3ltLW1vZGUAAAARL0NCQy9QS0NTNVBhZGRpbmc="));
        item.put("t", b642Av("AGIAAAAgeJcKzY3SHwBIhXdfxeYWd9UE5yX+RxaPJQ7L2TdgDxs="));
        item.put("V", b642Av("AG4AAAABMA=="));
        item.put("encAlg", b642Av("AGIAAAAgXJilRkdsIP0bqzvqutJc8AC8YhY1YApJCgTLXgAqtwU="));
        item.put("enc", b642Av("AGIAAABADvDUW2Ao1YWp7uxxEL+mv5uqHCrSNIDR18CgBD8XHCuNlBPC6GXxk9YnFmv3kgVDlMdEo0wE79zRoETB7GmjcA=="));
        item.put("intAlg", b642Av("AGIAAAAwI//7G2LUrAQ2EwQGQr7ZIKyXl1AlGeB+kfvZGmCj6wShZpMKPXjyBF/9RvIz3clQ"));
        item.put("N", b642Av("AHMAAAAMbWF0ZXJpYWxOYW1l"));
        item.put("int", b642Av("AGIAAABAzFha4J4gPaiwhjiQs47L0bTf4WSNemVAxKJJnBnujl7OajvO7ZW3zehGJlaai4tCLxTwoLPI+Ig/a+zCdau4iw=="));
        item.put("*amzn-ddb-map-sig*", b642Av("AGIAAAAgaklO+h7kSUjXEt6pBA03G4wiIU20XKT/sP+rKSeNAKc="));
        ddb.putItem(new PutItemRequest("metastore", item));
        item.clear();
    }

    private static AttributeValue b642Av(String b64) {
        return AttributeValueMarshaller.unmarshall(ByteBuffer.wrap(Base64
                .decode(b64)));
    }
}
