// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazonaws.services.dynamodbv2.datamodeling;

import com.amazonaws.services.dynamodbv2.AmazonDynamoDB;
import com.amazonaws.services.dynamodbv2.datamodeling.DynamoDBMapperConfig.SaveBehavior;
import com.amazonaws.services.dynamodbv2.datamodeling.encryption.DynamoDBEncryptor;
import com.amazonaws.services.dynamodbv2.datamodeling.encryption.providers.AsymmetricStaticProvider;
import com.amazonaws.services.dynamodbv2.datamodeling.encryption.providers.CachingMostRecentProvider;
import com.amazonaws.services.dynamodbv2.datamodeling.encryption.providers.DirectKmsMaterialProvider;
import com.amazonaws.services.dynamodbv2.datamodeling.encryption.providers.EncryptionMaterialsProvider;
import com.amazonaws.services.dynamodbv2.datamodeling.encryption.providers.SymmetricStaticProvider;
import com.amazonaws.services.dynamodbv2.datamodeling.encryption.providers.WrappedMaterialsProvider;
import com.amazonaws.services.dynamodbv2.datamodeling.encryption.providers.store.MetaStore;
import com.amazonaws.services.dynamodbv2.datamodeling.encryption.providers.store.ProviderStore;
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
import com.amazonaws.services.dynamodbv2.testing.AttributeValueDeserializer;
import com.amazonaws.services.dynamodbv2.testing.AttributeValueSerializer;
import com.amazonaws.services.dynamodbv2.testing.ScenarioManifest;
import com.amazonaws.services.dynamodbv2.testing.ScenarioManifest.KeyData;
import com.amazonaws.services.dynamodbv2.testing.ScenarioManifest.Keys;
import com.amazonaws.services.dynamodbv2.testing.ScenarioManifest.Scenario;
import com.amazonaws.services.dynamodbv2.testing.types.BaseClass;
import com.amazonaws.services.dynamodbv2.testing.types.HashKeyOnly;
import com.amazonaws.services.dynamodbv2.testing.types.KeysOnly;
import com.amazonaws.services.dynamodbv2.testing.types.Mixed;
import com.amazonaws.services.dynamodbv2.testing.types.SignOnly;
import com.amazonaws.services.dynamodbv2.testing.types.Untouched;
import com.amazonaws.services.kms.AWSKMS;
import com.amazonaws.services.kms.AWSKMSClientBuilder;
import com.amazonaws.util.Base64;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.module.SimpleModule;
import org.junit.Before;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.IOException;
import java.net.URL;
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
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static org.testng.AssertJUnit.assertEquals;
import static org.testng.AssertJUnit.assertFalse;
import static org.testng.AssertJUnit.assertNull;
import static org.testng.AssertJUnit.assertTrue;
import static org.testng.AssertJUnit.fail;

public class TransformerHolisticIT {
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
    private static final String HASH_KEY = "hashKey";
    private static final String RANGE_KEY = "rangeKey";
    private static final String RSA = "RSA";

    private AmazonDynamoDB client;
    private static AWSKMS kmsClient = AWSKMSClientBuilder.standard().build();

    private static Map<String, KeyData> keyDataMap = new HashMap<>();

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

    private static final String TEST_VECTOR_MANIFEST_DIR = "/vectors/encrypted_item/";
    private static final String SCENARIO_MANIFEST_PATH = TEST_VECTOR_MANIFEST_DIR + "scenarios.json";
    private static final String JAVA_DIR = "java";

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

    @DataProvider(name = "getEncryptTestVectors")
    public static Object[][] getEncryptTestVectors() throws IOException {
        ScenarioManifest scenarioManifest = getManifestFromFile(SCENARIO_MANIFEST_PATH,
                new TypeReference<ScenarioManifest>() {});
        loadKeyData(scenarioManifest.keyDataPath);

        // Only use Java generated test vectors to dedupe the scenarios for encrypt,
        // we only care that we are able to generate data using the different provider configurations
        List<Object[]> dedupedScenarios = scenarioManifest.scenarios.stream()
                .filter(s -> s.ciphertextPath.contains(JAVA_DIR))
                .map(s -> new Object[] { s })
                .collect(Collectors.toList());
        return dedupedScenarios.toArray(new Object[dedupedScenarios.size()][]);
    }

    @DataProvider(name = "getDecryptTestVectors")
    public static Object[][] getDecryptTestVectors() throws IOException {
        ScenarioManifest scenarioManifest = getManifestFromFile(SCENARIO_MANIFEST_PATH,
                new TypeReference<ScenarioManifest>() {});
        loadKeyData(scenarioManifest.keyDataPath);

        List<Object[]> scenarios = scenarioManifest.scenarios.stream()
                .map(s -> new Object[] { s })
                .collect(Collectors.toList());
        return scenarios.toArray(new Object[scenarios.size()][]);
    }

    // Set up for non-parameterized tests
    @Before
    public void setUp() {
        System.setProperty("sqlite4java.library.path", "target/test-lib");
        client = DynamoDBEmbedded.create();

        // load data into ciphertext tables
        createCiphertextTables(client);
    }

    @Test(dataProvider = "getDecryptTestVectors")
    public void decryptTestVector(Scenario scenario) throws IOException {
        System.setProperty("sqlite4java.library.path", "target/test-lib");
        client = DynamoDBEmbedded.create();

        // load data into ciphertext tables
        createCiphertextTables(client);

        // load data from vector file
        putDataFromFile(client, scenario.ciphertextPath);

        // create and load metastore table if necessary
        ProviderStore metastore = null;
        if (scenario.metastore != null) {
            MetaStore.createTable(client, scenario.metastore.tableName, new ProvisionedThroughput(100L, 100L));
            putDataFromFile(client, scenario.metastore.path);
            EncryptionMaterialsProvider metaProvider = createProvider(scenario.metastore.providerName,
                    scenario.materialName, scenario.metastore.keys, null);
            metastore = new MetaStore(client, scenario.metastore.tableName, DynamoDBEncryptor.getInstance(metaProvider));
        }

        // Create the mapper with the provider under test
        EncryptionMaterialsProvider provider = createProvider(scenario.providerName, scenario.materialName, scenario.keys, metastore);
        DynamoDBMapper mapper = new DynamoDBMapper(client,
                new DynamoDBMapperConfig(SaveBehavior.CLOBBER), new AttributeEncryptor(provider));

        // Verify successful decryption
        switch (scenario.version) {
            case "v0":
                assertVersionCompatibility(mapper);
                break;
            case "v1":
                assertVersionCompatibility_2(mapper);
                break;
            default:
                throw new IllegalStateException("Version " + scenario.version + " not yet implemented in test vector runner");
        }
    }

    @Test(dataProvider = "getEncryptTestVectors")
    public void encryptWithTestVector(Scenario scenario) throws IOException {
        System.setProperty("sqlite4java.library.path", "target/test-lib");
        client = DynamoDBEmbedded.create();

        // load data into ciphertext tables
        createCiphertextTables(client);

        // create and load metastore table if necessary
        ProviderStore metastore = null;
        if (scenario.metastore != null) {
            MetaStore.createTable(client, scenario.metastore.tableName, new ProvisionedThroughput(100L, 100L));
            putDataFromFile(client, scenario.metastore.path);
            EncryptionMaterialsProvider metaProvider = createProvider(scenario.metastore.providerName,
                    scenario.materialName, scenario.metastore.keys, null);
            metastore = new MetaStore(client, scenario.metastore.tableName, DynamoDBEncryptor.getInstance(metaProvider));
        }

        // Encrypt data with the provider under test, only ensure that no exception is thrown
        EncryptionMaterialsProvider provider = createProvider(scenario.providerName, scenario.materialName, scenario.keys, metastore);
        generateStandardData(provider);
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
     * combined with the {@link AttributeEncryptor}. Specifically it checks that {@link SaveBehavior#PUT} properly
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
        key.put(HASH_KEY, new AttributeValue().withN("0"));
        key.put(RANGE_KEY, new AttributeValue().withN("15"));
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

        // Uncomment the function below to print the generated data
        // in our test vector format.

        // printTablesAsTestVectors();
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

    // Prints all current tables in the expected test vector format.
    // You may need to edit the output to grab the tables you care about, or
    // separate the tables into separate files for test vectors (metastores e.g.).
    private void printTablesAsTestVectors() throws JsonProcessingException {
        ObjectMapper mapper = new ObjectMapper();
        SimpleModule module = new SimpleModule();
        module.addSerializer(AttributeValue.class, new AttributeValueSerializer());
        mapper.registerModule(module);

        Map<String, List<Map<String, AttributeValue>>> testVector = new HashMap<>();
        for (String table : client.listTables().getTableNames()) {
            ScanResult scanResult;
            Map<String, AttributeValue> lastKey = null;
            do {
                scanResult = client.scan(new ScanRequest().withTableName(table).withExclusiveStartKey(lastKey));
                lastKey = scanResult.getLastEvaluatedKey();

                testVector.put(table, scanResult.getItems());

            } while (lastKey != null);
        }
        String jsonResult = mapper.writerWithDefaultPrettyPrinter().writeValueAsString(testVector);
        System.out.println(jsonResult);
    }

    private EncryptionMaterialsProvider createProvider(String providerName, String materialName, Keys keys, ProviderStore metastore) {
        switch (providerName) {
            case ScenarioManifest.MOST_RECENT_PROVIDER_NAME:
                return new CachingMostRecentProvider(metastore, materialName, 1000);
            case ScenarioManifest.STATIC_PROVIDER_NAME:
                KeyData decryptKeyData = keyDataMap.get(keys.decryptName);
                KeyData verifyKeyData = keyDataMap.get(keys.verifyName);
                SecretKey decryptKey = new SecretKeySpec(Base64.decode(decryptKeyData.material), decryptKeyData.algorithm);
                SecretKey verifyKey = new SecretKeySpec(Base64.decode(verifyKeyData.material), verifyKeyData.algorithm);
                return new SymmetricStaticProvider(decryptKey, verifyKey);
            case ScenarioManifest.WRAPPED_PROVIDER_NAME:
                decryptKeyData = keyDataMap.get(keys.decryptName);
                verifyKeyData = keyDataMap.get(keys.verifyName);

                // This can be either the asymmetric provider, where we should test using it's explicit constructor,
                // or a wrapped symmetric where we use the wrapped materials constructor.
                if (decryptKeyData.keyType.equals(ScenarioManifest.SYMMETRIC_KEY_TYPE)) {
                    decryptKey = new SecretKeySpec(Base64.decode(decryptKeyData.material), decryptKeyData.algorithm);
                    verifyKey = new SecretKeySpec(Base64.decode(verifyKeyData.material), verifyKeyData.algorithm);
                    return new WrappedMaterialsProvider(decryptKey, decryptKey, verifyKey);
                } else {
                    KeyData encryptKeyData = keyDataMap.get(keys.encryptName);
                    KeyData signKeyData = keyDataMap.get(keys.signName);
                    try {
                        // Hardcoded to use RSA for asymmetric keys. If we include vectors with a different
                        // asymmetric scheme this will need to be updated.
                        KeyFactory rsaFact = KeyFactory.getInstance(RSA);

                        PublicKey encryptMaterial = rsaFact.generatePublic(new X509EncodedKeySpec(Base64
                                .decode(encryptKeyData.material)));
                        PrivateKey decryptMaterial = rsaFact.generatePrivate(new PKCS8EncodedKeySpec(Base64
                                .decode(decryptKeyData.material)));
                        KeyPair decryptPair = new KeyPair(encryptMaterial, decryptMaterial);


                        PublicKey verifyMaterial = rsaFact.generatePublic(new X509EncodedKeySpec(Base64
                                .decode(verifyKeyData.material)));
                        PrivateKey signingMaterial = rsaFact.generatePrivate(new PKCS8EncodedKeySpec(Base64
                                .decode(signKeyData.material)));
                        KeyPair sigPair = new KeyPair(verifyMaterial, signingMaterial);

                        return new AsymmetricStaticProvider(decryptPair, sigPair);
                    } catch (GeneralSecurityException ex) {
                        throw new RuntimeException(ex);
                    }
                }
            case ScenarioManifest.AWS_KMS_PROVIDER_NAME:
                return new DirectKmsMaterialProvider(kmsClient, keyDataMap.get(keys.decryptName).keyId);
            default:
                throw new IllegalStateException("Provider " + providerName + " not yet implemented in test vector runner");
        }
    }

    // Create empty tables for the ciphertext.
    // The underlying structure to these tables is hardcoded,
    // and we run all test vectors assuming the ciphertext matches the key schema for these tables.
    private void createCiphertextTables(AmazonDynamoDB client) {
        ArrayList<AttributeDefinition> attrDef = new ArrayList<AttributeDefinition>();
        attrDef.add(new AttributeDefinition().withAttributeName(HASH_KEY).withAttributeType(ScalarAttributeType.N));
        attrDef.add(new AttributeDefinition().withAttributeName(RANGE_KEY).withAttributeType(ScalarAttributeType.N));

        ArrayList<KeySchemaElement> keySchema = new ArrayList<KeySchemaElement>();
        keySchema.add(new KeySchemaElement().withAttributeName(HASH_KEY).withKeyType(KeyType.HASH));
        keySchema.add(new KeySchemaElement().withAttributeName(RANGE_KEY).withKeyType(KeyType.RANGE));

        client.createTable(new CreateTableRequest().withTableName("TableName")
                .withAttributeDefinitions(attrDef)
                .withKeySchema(keySchema)
                .withProvisionedThroughput(new ProvisionedThroughput(100L, 100L)));

        attrDef = new ArrayList<AttributeDefinition>();
        attrDef.add(new AttributeDefinition().withAttributeName(HASH_KEY).withAttributeType(ScalarAttributeType.S));
        keySchema = new ArrayList<KeySchemaElement>();
        keySchema.add(new KeySchemaElement().withAttributeName(HASH_KEY).withKeyType(KeyType.HASH));

        client.createTable(new CreateTableRequest().withTableName("HashKeyOnly")
                .withAttributeDefinitions(attrDef)
                .withKeySchema(keySchema)
                .withProvisionedThroughput(new ProvisionedThroughput(100L, 100L)));

        attrDef = new ArrayList<AttributeDefinition>();
        attrDef.add(new AttributeDefinition().withAttributeName(HASH_KEY).withAttributeType(ScalarAttributeType.B));
        attrDef.add(new AttributeDefinition().withAttributeName(RANGE_KEY).withAttributeType(ScalarAttributeType.N));

        keySchema = new ArrayList<KeySchemaElement>();
        keySchema.add(new KeySchemaElement().withAttributeName(HASH_KEY).withKeyType(KeyType.HASH));
        keySchema.add(new KeySchemaElement().withAttributeName(RANGE_KEY).withKeyType(KeyType.RANGE));

        client.createTable(new CreateTableRequest().withTableName("DeterministicTable")
                .withAttributeDefinitions(attrDef)
                .withKeySchema(keySchema)
                .withProvisionedThroughput(new ProvisionedThroughput(100L, 100L)));
    }

    // Given a file in the test vector ciphertext format, put those entries into their tables.
    // This assumes the expected tables have already been created.
    private void putDataFromFile(AmazonDynamoDB client, String filename) throws IOException {
        Map<String, List<Map<String, AttributeValue>>> manifest = getCiphertextManifestFromFile(filename);
        for (String tableName : manifest.keySet()) {
            for (Map<String, AttributeValue> attributes : manifest.get(tableName)) {
                client.putItem(new PutItemRequest(tableName, attributes));
            }
        }
    }

    private Map<String, List<Map<String, AttributeValue>>> getCiphertextManifestFromFile(String filename) throws IOException {
        return getManifestFromFile(TEST_VECTOR_MANIFEST_DIR + stripFilePath(filename),
                new TypeReference<Map<String, List<Map<String, DeserializedAttributeValue>>>>() {});
    }

    private static <T> T getManifestFromFile(String filename, TypeReference typeRef) throws IOException {
        final URL url = TransformerHolisticIT.class.getResource(filename);
        if (url == null) {
            throw new IllegalStateException("Missing file " + filename + " in src/test/resources.");
        }
        final File manifestFile = new File(url.getPath());
        final ObjectMapper manifestMapper = new ObjectMapper();
        return manifestMapper.readValue(
                manifestFile,
                typeRef
        );
    }

    private static void loadKeyData(String filename) throws IOException {
        keyDataMap = getManifestFromFile(TEST_VECTOR_MANIFEST_DIR + stripFilePath(filename),
                new TypeReference<Map<String, KeyData>>() {});
    }

    private static String stripFilePath(String path) {
        return path.replaceFirst("file://", "");
    }

    @JsonDeserialize(using = AttributeValueDeserializer.class)
    public static class DeserializedAttributeValue extends AttributeValue {
    }
}
