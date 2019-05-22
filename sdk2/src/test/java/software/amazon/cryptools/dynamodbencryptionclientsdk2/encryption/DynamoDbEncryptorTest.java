/*
 * Copyright 2014-2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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
package software.amazon.cryptools.dynamodbencryptionclientsdk2.encryption;

import static java.util.Arrays.asList;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.testng.AssertJUnit.assertEquals;
import static org.testng.AssertJUnit.assertFalse;
import static org.testng.AssertJUnit.assertNotNull;
import static org.testng.AssertJUnit.assertNull;
import static org.testng.AssertJUnit.assertTrue;
import static software.amazon.cryptools.dynamodbencryptionclientsdk2.encryption.EncryptionContextOperators.overrideEncryptionContextTableName;

import java.lang.reflect.Method;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.cryptools.dynamodbencryptionclientsdk2.DynamoDbEncryptionConfiguration;
import software.amazon.cryptools.dynamodbencryptionclientsdk2.EncryptionAction;
import software.amazon.cryptools.dynamodbencryptionclientsdk2.encryption.exceptions.DynamoDbEncryptionException;
import software.amazon.cryptools.dynamodbencryptionclientsdk2.encryption.materials.DecryptionMaterials;
import software.amazon.cryptools.dynamodbencryptionclientsdk2.encryption.materials.EncryptionMaterials;
import software.amazon.cryptools.dynamodbencryptionclientsdk2.encryption.providers.EncryptionMaterialsProvider;
import software.amazon.cryptools.dynamodbencryptionclientsdk2.encryption.providers.SymmetricStaticProvider;
import software.amazon.cryptools.dynamodbencryptionclientsdk2.internal.Utils;
import software.amazon.cryptools.dynamodbencryptionclientsdk2.testing.AttrMatcher;
import software.amazon.cryptools.dynamodbencryptionclientsdk2.testing.EncryptionTestHelper;

public class DynamoDbEncryptorTest {
    private static SecretKey encryptionKey;
    private static SecretKey macKey;
    
    private InstrumentedEncryptionMaterialsProvider prov;
    private DynamoDbEncryptor encryptor;
    private Map<String, AttributeValue> attribs;
    private EncryptionContext context;
    private static final String OVERRIDDEN_TABLE_NAME = "TheBestTableName";

    @BeforeClass
    public static void setUpClass() throws Exception {
        KeyGenerator aesGen = KeyGenerator.getInstance("AES");
        aesGen.init(128, Utils.getRng());
        encryptionKey = aesGen.generateKey();
        
        KeyGenerator macGen = KeyGenerator.getInstance("HmacSHA256");
        macGen.init(256, Utils.getRng());
        macKey = macGen.generateKey();
    }
    
    @BeforeMethod
    public void setUp() {
        prov = new InstrumentedEncryptionMaterialsProvider(
                    new SymmetricStaticProvider(encryptionKey, macKey,
                        Collections.emptyMap()));
        encryptor = new DynamoDbEncryptor(prov, "encryptor-");
        
        attribs = new HashMap<>();
        attribs.put("intValue", AttributeValue.builder().n("123").build());
        attribs.put("stringValue", AttributeValue.builder().s("Hello world!").build());
        attribs.put("byteArrayValue",
                    AttributeValue.builder().b(SdkBytes.fromByteArray(new byte[] {0, 1, 2, 3, 4, 5})).build());
        attribs.put("stringSet", AttributeValue.builder().ss("Goodbye", "Cruel", "World", "?").build());
        attribs.put("intSet", AttributeValue.builder().ns("1", "200", "10", "15", "0").build());
        attribs.put("hashKey", AttributeValue.builder().n("5").build());
        attribs.put("rangeKey", AttributeValue.builder().n("7").build());
        attribs.put("version", AttributeValue.builder().n("0").build());

        // New(er) data types
        attribs.put("booleanTrue", AttributeValue.builder().bool(true).build());
        attribs.put("booleanFalse", AttributeValue.builder().bool(false).build());
        attribs.put("nullValue", AttributeValue.builder().nul(true).build());
        Map<String, AttributeValue> tmpMap = new HashMap<>(attribs);
        attribs.put("listValue", AttributeValue.builder().l(
                AttributeValue.builder().s("I'm a string").build(),
                AttributeValue.builder().n("42").build(),
                AttributeValue.builder().s("Another string").build(),
                AttributeValue.builder().ns("1", "4", "7").build(),
                AttributeValue.builder().m(tmpMap).build(),
                AttributeValue.builder().l(
                        AttributeValue.builder().n("123").build(),
                        AttributeValue.builder().ns("1", "200", "10", "15", "0").build(),
                        AttributeValue.builder().ss("Goodbye", "Cruel", "World", "!").build()
                ).build()).build());
        tmpMap = new HashMap<>();
        tmpMap.put("another string", AttributeValue.builder().s("All around the cobbler's bench").build());
        tmpMap.put("next line", AttributeValue.builder().ss("the monkey", "chased", "the weasel").build());
        tmpMap.put("more lyrics", AttributeValue.builder().l(
                AttributeValue.builder().s("the monkey").build(),
                AttributeValue.builder().s("thought twas").build(),
                AttributeValue.builder().s("all in fun").build()
        ).build());
        tmpMap.put("weasel", AttributeValue.builder().m(Collections.singletonMap("pop", AttributeValue.builder().bool(true).build())).build());
        attribs.put("song", AttributeValue.builder().m(tmpMap).build());


        context = EncryptionContext.builder()
            .tableName("TableName")
            .hashKeyName("hashKey")
            .rangeKeyName("rangeKey")
            .build();
    }

    @Test
    public void testSetSignatureFieldName() {
        assertNotNull(encryptor.getSignatureFieldName());
        encryptor.setSignatureFieldName("A different value");
        assertEquals("A different value", encryptor.getSignatureFieldName());
    }

    @Test
    public void testSetMaterialDescriptionFieldName() {
        assertNotNull(encryptor.getMaterialDescriptionFieldName());
        encryptor.setMaterialDescriptionFieldName("A different value");
        assertEquals("A different value", encryptor.getMaterialDescriptionFieldName());
    }
    
    @Test
    public void fullEncryption() {
        Map<String, AttributeValue> encryptedAttributes = EncryptionTestHelper.encryptAllFieldsExcept(encryptor,
            Collections.unmodifiableMap(attribs), context, asList("hashKey", "rangeKey", "version"));
        assertThat(encryptedAttributes, AttrMatcher.invert(attribs));

        Map<String, AttributeValue> decryptedAttributes = EncryptionTestHelper.decryptAllFieldsExcept(encryptor,
            Collections.unmodifiableMap(encryptedAttributes), context, asList("hashKey", "rangeKey", "version"));
        assertThat(decryptedAttributes, AttrMatcher.match(attribs));

        // Make sure keys and version are not encrypted
        assertAttrEquals(attribs.get("hashKey"), encryptedAttributes.get("hashKey"));
        assertAttrEquals(attribs.get("rangeKey"), encryptedAttributes.get("rangeKey"));
        assertAttrEquals(attribs.get("version"), encryptedAttributes.get("version"));

        // Make sure String has been encrypted (we'll assume the others are correct as well)
        assertTrue(encryptedAttributes.containsKey("stringValue"));
        assertNull(encryptedAttributes.get("stringValue").s());
        assertNotNull(encryptedAttributes.get("stringValue").b());

        // Make sure we're calling the proper getEncryptionMaterials method
        assertEquals("Wrong getEncryptionMaterials() called", 
                1, prov.getCallCount("getEncryptionMaterials(EncryptionContext context)"));
    }

    @Test(expectedExceptions = IllegalArgumentException.class)
    public void encryptWithDefaultEncryptionActionOfNullWithKeyOverridesThrowsIllegalArgumentException() {
        DynamoDbEncryptionConfiguration configuration = DynamoDbEncryptionConfiguration.builder()
           .addEncryptionActionOverride("hashKey", EncryptionAction.SIGN_ONLY)
           .addEncryptionActionOverride("rangeKey", EncryptionAction.SIGN_ONLY)
           .addEncryptionActionOverride("version", EncryptionAction.SIGN_ONLY)
           .encryptionContext(context)
           .build();

        encryptor.encryptRecord(Collections.unmodifiableMap(attribs), configuration);
    }

    @Test(expectedExceptions = IllegalArgumentException.class)
    public void decryptWithDefaultEncryptionActionOfNullWithKeyOverridesThrowsIllegalArgumentException() {
        DynamoDbEncryptionConfiguration configuration = DynamoDbEncryptionConfiguration.builder()
           .addEncryptionActionOverride("hashKey", EncryptionAction.SIGN_ONLY)
           .addEncryptionActionOverride("rangeKey", EncryptionAction.SIGN_ONLY)
           .addEncryptionActionOverride("version", EncryptionAction.SIGN_ONLY)
           .encryptionContext(context)
           .build();

        encryptor.decryptRecord(Collections.unmodifiableMap(attribs), configuration);
    }

    @Test
    public void defaultEncryptionActionOfSignAndEncryptWithKeyOverrides() {
        DynamoDbEncryptionConfiguration configuration = DynamoDbEncryptionConfiguration.builder()
            .defaultEncryptionAction(EncryptionAction.ENCRYPT_AND_SIGN)
            .addEncryptionActionOverride("hashKey", EncryptionAction.SIGN_ONLY)
            .addEncryptionActionOverride("rangeKey", EncryptionAction.SIGN_ONLY)
            .addEncryptionActionOverride("version", EncryptionAction.SIGN_ONLY)
            .encryptionContext(context)
            .build();

        Map<String, AttributeValue> encryptedAttributes =
            encryptor.encryptRecord(Collections.unmodifiableMap(attribs), configuration);
        assertThat(encryptedAttributes, AttrMatcher.invert(attribs));
        Map<String, AttributeValue> decryptedAttributes =
            encryptor.decryptRecord(Collections.unmodifiableMap(encryptedAttributes), configuration);
        assertThat(decryptedAttributes, AttrMatcher.match(attribs));

        // Make sure keys and version are not encrypted
        assertAttrEquals(attribs.get("hashKey"), encryptedAttributes.get("hashKey"));
        assertAttrEquals(attribs.get("rangeKey"), encryptedAttributes.get("rangeKey"));
        assertAttrEquals(attribs.get("version"), encryptedAttributes.get("version"));

        // Make sure String has been encrypted (we'll assume the others are correct as well)
        assertTrue(encryptedAttributes.containsKey("stringValue"));
        assertNull(encryptedAttributes.get("stringValue").s());
        assertNotNull(encryptedAttributes.get("stringValue").b());

        // Make sure we're calling the proper getEncryptionMaterials method
        assertEquals("Wrong getEncryptionMaterials() called",
                     1, prov.getCallCount("getEncryptionMaterials(EncryptionContext context)"));
    }

    @Test
    public void defaultEncryptionActionOfSignOnlyWithNoOverrides() {
        DynamoDbEncryptionConfiguration configuration = DynamoDbEncryptionConfiguration.builder()
            .defaultEncryptionAction(EncryptionAction.SIGN_ONLY)
            .encryptionContext(context)
            .build();

        Map<String, AttributeValue> encryptedAttributes =
            encryptor.encryptRecord(Collections.unmodifiableMap(attribs), configuration);
        assertThat(encryptedAttributes, AttrMatcher.invert(attribs));
        Map<String, AttributeValue> decryptedAttributes =
            encryptor.decryptRecord(Collections.unmodifiableMap(encryptedAttributes), configuration);
        assertThat(decryptedAttributes, AttrMatcher.match(attribs));

        // Verify that nothing actually got encrypted
        Map<String, AttributeValue> copyOfEncryptedAttributes = new HashMap<>(encryptedAttributes);
        copyOfEncryptedAttributes.remove(encryptor.getMaterialDescriptionFieldName());
        copyOfEncryptedAttributes.remove(encryptor.getSignatureFieldName());
        assertThat(copyOfEncryptedAttributes, AttrMatcher.match(attribs));
    }

    @Test
    public void defaultEncryptionActionOfIgnoreWithNoOverrides() {
        DynamoDbEncryptionConfiguration configuration = DynamoDbEncryptionConfiguration.builder()
            .defaultEncryptionAction(EncryptionAction.DO_NOTHING)
            .encryptionContext(context)
            .build();

        Map<String, AttributeValue> encryptedAttributes =
            new HashMap<>(encryptor.encryptRecord(Collections.unmodifiableMap(attribs), configuration));

        // Verify that nothing actually got encrypted
        Map<String, AttributeValue> copyOfEncryptedAttributes = new HashMap<>(encryptedAttributes);
        copyOfEncryptedAttributes.remove(encryptor.getMaterialDescriptionFieldName());
        copyOfEncryptedAttributes.remove(encryptor.getSignatureFieldName());
        assertThat(copyOfEncryptedAttributes, AttrMatcher.match(attribs));

        // Now modify one of the attributes and decrypt to prove that it was not signed
        Map<String, AttributeValue> copyOfAttributes = new HashMap<>(attribs);
        encryptedAttributes.put("stringValue", AttributeValue.builder().s("Goodbye world!").build());
        copyOfAttributes.put("stringValue", AttributeValue.builder().s("Goodbye world!").build());
        Map<String, AttributeValue> decryptedAttributes = encryptor.decryptRecord(encryptedAttributes, configuration);
        assertThat(decryptedAttributes, AttrMatcher.match(copyOfAttributes));
    }

    @Test
    public void ensureEncryptedAttributesUnmodified() {
        Map<String, AttributeValue> encryptedAttributes =
                EncryptionTestHelper.encryptAllFieldsExcept(encryptor, Collections.unmodifiableMap(attribs), context, asList("hashKey", "rangeKey", "version"));
        String encryptedString = encryptedAttributes.toString();
        EncryptionTestHelper.decryptAllFieldsExcept(encryptor, Collections.unmodifiableMap(encryptedAttributes), context, asList("hashKey", "rangeKey", "version"));

        assertEquals(encryptedString, encryptedAttributes.toString());
    }

    @Test(expectedExceptions = DynamoDbEncryptionException.class)
    public void fullEncryptionBadSignature() {
        Map<String, AttributeValue> encryptedAttributes =
                EncryptionTestHelper.encryptAllFieldsExcept(encryptor, Collections.unmodifiableMap(attribs), context, asList("hashKey", "rangeKey", "version"));
        assertThat(encryptedAttributes, AttrMatcher.invert(attribs));
        Map<String, AttributeValue> modifiedEncryptedAttributes = new HashMap<>(encryptedAttributes);
        modifiedEncryptedAttributes.put("hashKey", AttributeValue.builder().n("666").build());
        EncryptionTestHelper.decryptAllFieldsExcept(encryptor, Collections.unmodifiableMap(modifiedEncryptedAttributes), context, asList("hashKey", "rangeKey", "version"));
    }
    
    @Test(expectedExceptions =IllegalArgumentException.class)
    public void badVersionNumber() {
        Map<String, AttributeValue> encryptedAttributes =
                EncryptionTestHelper.encryptAllFieldsExcept(encryptor, Collections.unmodifiableMap(attribs), context, asList("hashKey", "rangeKey", "version"));
        byte[] rawArray = encryptedAttributes.get(encryptor.getMaterialDescriptionFieldName()).b().asByteArray();
        assertEquals(0, rawArray[0]); // This will need to be kept in sync with the current version.
        rawArray[0] = 100;
        encryptedAttributes.put(encryptor.getMaterialDescriptionFieldName(),
                                AttributeValue.builder().b(SdkBytes.fromByteArray(rawArray)).build());
        EncryptionTestHelper.decryptAllFieldsExcept(encryptor, Collections.unmodifiableMap(encryptedAttributes), context, asList("hashKey", "rangeKey", "version"));
    }
    
    @Test
    public void signedOnly() {
        Map<String, AttributeValue> encryptedAttributes = 
                EncryptionTestHelper.encryptAllFieldsExcept(encryptor, attribs, context, attribs.keySet());
        assertThat(encryptedAttributes, AttrMatcher.invert(attribs));
        Map<String, AttributeValue> decryptedAttributes =
                EncryptionTestHelper.decryptAllFieldsExcept(encryptor, encryptedAttributes, context, attribs.keySet());
        assertThat(decryptedAttributes, AttrMatcher.match(attribs));
        
        // Make sure keys and version are not encrypted
        assertAttrEquals(attribs.get("hashKey"), encryptedAttributes.get("hashKey"));
        assertAttrEquals(attribs.get("rangeKey"), encryptedAttributes.get("rangeKey"));
        assertAttrEquals(attribs.get("version"), encryptedAttributes.get("version"));
        
        // Make sure String has not been encrypted (we'll assume the others are correct as well)
        assertAttrEquals(attribs.get("stringValue"), encryptedAttributes.get("stringValue"));
    }
    
    @Test
    public void signedOnlyNullCryptoKey() {
        prov = new InstrumentedEncryptionMaterialsProvider(
                new SymmetricStaticProvider(null, macKey, Collections.emptyMap()));
        encryptor = new DynamoDbEncryptor(prov, "encryptor-");
        Map<String, AttributeValue> encryptedAttributes = 
                EncryptionTestHelper.encryptAllFieldsExcept(encryptor, attribs, context, attribs.keySet());
        assertThat(encryptedAttributes, AttrMatcher.invert(attribs));
        Map<String, AttributeValue> decryptedAttributes = EncryptionTestHelper.decryptAllFieldsExcept(encryptor, encryptedAttributes, context, attribs.keySet());
        assertThat(decryptedAttributes, AttrMatcher.match(attribs));
        
        // Make sure keys and version are not encrypted
        assertAttrEquals(attribs.get("hashKey"), encryptedAttributes.get("hashKey"));
        assertAttrEquals(attribs.get("rangeKey"), encryptedAttributes.get("rangeKey"));
        assertAttrEquals(attribs.get("version"), encryptedAttributes.get("version"));
        
        // Make sure String has not been encrypted (we'll assume the others are correct as well)
        assertAttrEquals(attribs.get("stringValue"), encryptedAttributes.get("stringValue"));
    }
    
    @Test(expectedExceptions = DynamoDbEncryptionException.class)
    public void signedOnlyBadSignature() {
        Map<String, AttributeValue> encryptedAttributes = 
                EncryptionTestHelper.encryptAllFieldsExcept(encryptor, attribs, context, attribs.keySet());
        assertThat(encryptedAttributes, AttrMatcher.invert(attribs));
        Map<String, AttributeValue> modifiedEncryptedAttributes = new HashMap<>(encryptedAttributes);
        modifiedEncryptedAttributes.put("hashKey", AttributeValue.builder().n("666").build());
        EncryptionTestHelper.decryptAllFieldsExcept(encryptor, modifiedEncryptedAttributes, context, attribs.keySet());
    }
    
    @Test(expectedExceptions = DynamoDbEncryptionException.class)
    public void signedOnlyNoSignature() {
        Map<String, AttributeValue> encryptedAttributes = 
                EncryptionTestHelper.encryptAllFieldsExcept(encryptor, attribs, context, attribs.keySet());
        assertThat(encryptedAttributes, AttrMatcher.invert(attribs));
        encryptedAttributes.remove(encryptor.getSignatureFieldName());
        EncryptionTestHelper.decryptAllFieldsExcept(encryptor, encryptedAttributes, context, attribs.keySet());
    }
    
    @Test
    public void RsaSignedOnly() throws GeneralSecurityException {
        KeyPairGenerator rsaGen = KeyPairGenerator.getInstance("RSA");
        rsaGen.initialize(2048, Utils.getRng());
        KeyPair sigPair = rsaGen.generateKeyPair();
        encryptor = new DynamoDbEncryptor(
            new SymmetricStaticProvider(encryptionKey, sigPair,
                    Collections.emptyMap()), "encryptor-");
        
        Map<String, AttributeValue> encryptedAttributes = EncryptionTestHelper.encryptAllFieldsExcept(encryptor, attribs, context, attribs.keySet());
        assertThat(encryptedAttributes, AttrMatcher.invert(attribs));
        Map<String, AttributeValue> decryptedAttributes = 
                EncryptionTestHelper.decryptAllFieldsExcept(encryptor, encryptedAttributes, context, attribs.keySet());
        assertThat(decryptedAttributes, AttrMatcher.match(attribs));
        
        // Make sure keys and version are not encrypted
        assertAttrEquals(attribs.get("hashKey"), encryptedAttributes.get("hashKey"));
        assertAttrEquals(attribs.get("rangeKey"), encryptedAttributes.get("rangeKey"));
        assertAttrEquals(attribs.get("version"), encryptedAttributes.get("version"));
        
        // Make sure String has not been encrypted (we'll assume the others are correct as well)
        assertAttrEquals(attribs.get("stringValue"), encryptedAttributes.get("stringValue"));
    }
    
    @Test(expectedExceptions = DynamoDbEncryptionException.class)
    public void RsaSignedOnlyBadSignature() throws GeneralSecurityException {
        KeyPairGenerator rsaGen = KeyPairGenerator.getInstance("RSA");
        rsaGen.initialize(2048, Utils.getRng());
        KeyPair sigPair = rsaGen.generateKeyPair();
        encryptor = new DynamoDbEncryptor(
            new SymmetricStaticProvider(encryptionKey, sigPair,
                    Collections.emptyMap()), "encryptor-");
        
        Map<String, AttributeValue> encryptedAttributes = EncryptionTestHelper.encryptAllFieldsExcept(encryptor, attribs, context, attribs.keySet());
        assertThat(encryptedAttributes, AttrMatcher.invert(attribs));
        Map<String, AttributeValue> modifiedEncryptedAttributes = new HashMap<>(encryptedAttributes);
        modifiedEncryptedAttributes.put("hashKey", AttributeValue.builder().n("666").build());
        EncryptionTestHelper.decryptAllFieldsExcept(encryptor, modifiedEncryptedAttributes, context, attribs.keySet());
    }

    /**
     * Tests that no exception is thrown when the encryption context override operator is null
     */
    @Test
    public void testNullEncryptionContextOperator() {
        DynamoDbEncryptor encryptor = new DynamoDbEncryptor(prov);
        encryptor.setEncryptionContextOverrideOperator(null);
        EncryptionTestHelper.encryptAllFieldsExcept(encryptor, attribs, context, Collections.emptyList());
    }

    /**
     * Tests decrypt and encrypt with an encryption context override operator
     */
    @Test
    public void testTableNameOverriddenEncryptionContextOperator() {
        // Ensure that the table name is different from what we override the table to.
        assertThat(context.getTableName(), not(equalTo(OVERRIDDEN_TABLE_NAME)));
        DynamoDbEncryptor encryptor = new DynamoDbEncryptor(prov);
        encryptor.setEncryptionContextOverrideOperator(overrideEncryptionContextTableName(context.getTableName(), OVERRIDDEN_TABLE_NAME));
        Map<String, AttributeValue> encryptedItems = EncryptionTestHelper.encryptAllFieldsExcept(encryptor, attribs, context, Collections.emptyList());
        Map<String, AttributeValue> decryptedItems = EncryptionTestHelper.decryptAllFieldsExcept(encryptor, encryptedItems, context, Collections.emptyList());
        assertThat(decryptedItems, AttrMatcher.match(attribs));
    }


    /**
     * Tests encrypt with an encryption context override operator, and a second encryptor without an override
     */
    @Test
    public void testTableNameOverriddenEncryptionContextOperatorWithSecondEncryptor() {
        // Ensure that the table name is different from what we override the table to.
        assertThat(context.getTableName(), not(equalTo(OVERRIDDEN_TABLE_NAME)));
        DynamoDbEncryptor encryptor = new DynamoDbEncryptor(prov);
        DynamoDbEncryptor encryptorWithoutOverride = new DynamoDbEncryptor(prov);
        encryptor.setEncryptionContextOverrideOperator(overrideEncryptionContextTableName(context.getTableName(), OVERRIDDEN_TABLE_NAME));
        Map<String, AttributeValue> encryptedItems = EncryptionTestHelper.encryptAllFieldsExcept(encryptor, attribs, context, Collections.emptyList());

        EncryptionContext expectedOverriddenContext = context.toBuilder().tableName("TheBestTableName").build();
        Map<String, AttributeValue> decryptedItems =
            EncryptionTestHelper.decryptAllFieldsExcept(encryptorWithoutOverride, encryptedItems, expectedOverriddenContext, Collections.emptyList());
        assertThat(decryptedItems, AttrMatcher.match(attribs));
    }

    /**
     * Tests encrypt with an encryption context override operator, and a second encryptor without an override
     */
    @Test(expectedExceptions = DynamoDbEncryptionException.class)
    public void testTableNameOverriddenEncryptionContextOperatorWithSecondEncryptorButTheOriginalEncryptionContext() {
        // Ensure that the table name is different from what we override the table to.
        assertThat(context.getTableName(), not(equalTo(OVERRIDDEN_TABLE_NAME)));
        DynamoDbEncryptor encryptor = new DynamoDbEncryptor(prov);
        DynamoDbEncryptor encryptorWithoutOverride = new DynamoDbEncryptor(prov);
        encryptor.setEncryptionContextOverrideOperator(overrideEncryptionContextTableName(context.getTableName(), OVERRIDDEN_TABLE_NAME));
        Map<String, AttributeValue> encryptedItems = EncryptionTestHelper.encryptAllFieldsExcept(encryptor, attribs, context, Collections.emptyList());

        // Use the original encryption context, and expect a signature failure
        EncryptionTestHelper.decryptAllFieldsExcept(encryptorWithoutOverride, encryptedItems, context, Collections.emptyList());
    }

    @Test
    public void EcdsaSignedOnly() throws GeneralSecurityException {
        encryptor = new DynamoDbEncryptor(getMaterialProviderwithECDSA());
        
        Map<String, AttributeValue> encryptedAttributes = EncryptionTestHelper.encryptAllFieldsExcept(encryptor, attribs, context, attribs.keySet());
        assertThat(encryptedAttributes, AttrMatcher.invert(attribs));
        Map<String, AttributeValue> decryptedAttributes = 
                EncryptionTestHelper.decryptAllFieldsExcept(encryptor, encryptedAttributes, context, attribs.keySet());
        assertThat(decryptedAttributes, AttrMatcher.match(attribs));
        
        // Make sure keys and version are not encrypted
        assertAttrEquals(attribs.get("hashKey"), encryptedAttributes.get("hashKey"));
        assertAttrEquals(attribs.get("rangeKey"), encryptedAttributes.get("rangeKey"));
        assertAttrEquals(attribs.get("version"), encryptedAttributes.get("version"));
        
        // Make sure String has not been encrypted (we'll assume the others are correct as well)
        assertAttrEquals(attribs.get("stringValue"), encryptedAttributes.get("stringValue"));
    }
    
    @Test(expectedExceptions = DynamoDbEncryptionException.class)
    public void EcdsaSignedOnlyBadSignature() throws GeneralSecurityException {

        encryptor = new DynamoDbEncryptor(getMaterialProviderwithECDSA());

        Map<String, AttributeValue> encryptedAttributes = EncryptionTestHelper.encryptAllFieldsExcept(encryptor, attribs, context, attribs.keySet());
        assertThat(encryptedAttributes, AttrMatcher.invert(attribs));
        Map<String, AttributeValue> modifiedEncryptedAttributes = new HashMap<>(encryptedAttributes);
        modifiedEncryptedAttributes.put("hashKey", AttributeValue.builder().n("666").build());
        EncryptionTestHelper.decryptAllFieldsExcept(encryptor, modifiedEncryptedAttributes, context, attribs.keySet());
    }

    @Test
    public void toByteArray() throws ReflectiveOperationException {
        final byte[] expected = new byte[] {0, 1, 2, 3, 4, 5};
        assertToByteArray("Wrap", expected, ByteBuffer.wrap(expected));
        assertToByteArray("Wrap-RO", expected, ByteBuffer.wrap(expected).asReadOnlyBuffer());

        assertToByteArray("Wrap-Truncated-Sliced", expected, ByteBuffer.wrap(new byte[] {0, 1, 2, 3, 4, 5, 6}, 0, 6).slice());
        assertToByteArray("Wrap-Offset-Sliced", expected, ByteBuffer.wrap(new byte[] {6, 0, 1, 2, 3, 4, 5, 6}, 1, 6).slice());
        assertToByteArray("Wrap-Truncated", expected, ByteBuffer.wrap(new byte[] {0, 1, 2, 3, 4, 5, 6}, 0, 6));
        assertToByteArray("Wrap-Offset", expected, ByteBuffer.wrap(new byte[] {6, 0, 1, 2, 3, 4, 5, 6}, 1, 6));

        ByteBuffer buff = ByteBuffer.allocate(expected.length + 10);
        buff.put(expected);
        buff.flip();
        assertToByteArray("Normal", expected, buff);

        buff = ByteBuffer.allocateDirect(expected.length + 10);
        buff.put(expected);
        buff.flip();
        assertToByteArray("Direct", expected, buff);
    }

    @Test(expectedExceptions = IllegalArgumentException.class)
    public void encryptWithNullAttributeValuesThrowsIllegalArgumentException() {
        encryptor.encryptRecord(null, DynamoDbEncryptionConfiguration.builder().encryptionContext(context).build());
    }

    @Test(expectedExceptions = IllegalArgumentException.class)
    public void encryptWithNullEncryptionContextThrowsIllegalArgumentException() {
        encryptor.encryptRecord(attribs, DynamoDbEncryptionConfiguration.builder().build());
    }

    private void assertToByteArray(final String msg, final byte[] expected, final ByteBuffer testValue) throws ReflectiveOperationException {
        Method m = DynamoDbEncryptor.class.getDeclaredMethod("toByteArray", ByteBuffer.class);
        m.setAccessible(true);

        int oldPosition = testValue.position();
        int oldLimit = testValue.limit();

        assertThat(m.invoke(null, testValue), is(expected));
        assertEquals(msg + ":Position", oldPosition, testValue.position());
        assertEquals(msg + ":Limit", oldLimit, testValue.limit());
    }

    private void assertAttrEquals(AttributeValue o1, AttributeValue o2) {
        assertEquals(o1.b(), o2.b());
        assertSetsEqual(o1.bs(), o2.bs());
        assertEquals(o1.n(), o2.n());
        assertSetsEqual(o1.ns(), o2.ns());
        assertEquals(o1.s(), o2.s());
        assertSetsEqual(o1.ss(), o2.ss());
    }
    
    private <T> void assertSetsEqual(Collection<T> c1, Collection<T> c2) {
        assertFalse(c1 == null ^ c2 == null);
        if (c1 != null) {
            Set<T> s1 = new HashSet<>(c1);
            Set<T> s2 = new HashSet<>(c2);
            assertEquals(s1, s2);
        }
    }

    private EncryptionMaterialsProvider getMaterialProviderwithECDSA() 
           throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, NoSuchProviderException {
            Security.addProvider(new BouncyCastleProvider());
            ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("secp384r1");
            KeyPairGenerator g = KeyPairGenerator.getInstance("ECDSA", "BC");
            g.initialize(ecSpec, Utils.getRng());
            KeyPair keypair = g.generateKeyPair();
            Map<String, String> description = new HashMap<>();
            description.put(DynamoDbEncryptor.DEFAULT_SIGNING_ALGORITHM_HEADER, "SHA384withECDSA");
            return new SymmetricStaticProvider(null, keypair, description);
    }

    private static final class InstrumentedEncryptionMaterialsProvider implements EncryptionMaterialsProvider {
        private final EncryptionMaterialsProvider delegate;
        private final ConcurrentHashMap<String, AtomicInteger> calls = new ConcurrentHashMap<>();
        
        InstrumentedEncryptionMaterialsProvider(EncryptionMaterialsProvider delegate) {
            this.delegate = delegate;
        }
        
        @Override
        public DecryptionMaterials getDecryptionMaterials(EncryptionContext context) {
            incrementMethodCount("getDecryptionMaterials()");
            return delegate.getDecryptionMaterials(context);
        }

        @Override
        public EncryptionMaterials getEncryptionMaterials(EncryptionContext context) {
            incrementMethodCount("getEncryptionMaterials(EncryptionContext context)");
            return delegate.getEncryptionMaterials(context);
        }

        @Override
        public void refresh() {
            incrementMethodCount("refresh()");
            delegate.refresh();
        }
        
        int getCallCount(String method) {
            AtomicInteger count = calls.get(method);
            if (count != null) {
                return count.intValue();
            } else {
                return 0;
            }
        }
        
        @SuppressWarnings("unused")
        public void resetCallCounts() {
            calls.clear();
        }
        
        private void incrementMethodCount(String method) {
            AtomicInteger oldValue = calls.putIfAbsent(method, new AtomicInteger(1));
            if (oldValue != null) {
                oldValue.incrementAndGet();
            }
        }
    }
}
