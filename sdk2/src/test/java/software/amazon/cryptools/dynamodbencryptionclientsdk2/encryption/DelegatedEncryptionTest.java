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
import static org.testng.AssertJUnit.assertEquals;
import static org.testng.AssertJUnit.assertFalse;
import static org.testng.AssertJUnit.assertNotNull;
import static org.testng.AssertJUnit.assertNull;
import static org.testng.AssertJUnit.assertTrue;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import javax.crypto.spec.SecretKeySpec;

import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.cryptools.dynamodbencryptionclientsdk2.encryption.exceptions.DynamoDbEncryptionException;
import software.amazon.cryptools.dynamodbencryptionclientsdk2.encryption.providers.EncryptionMaterialsProvider;
import software.amazon.cryptools.dynamodbencryptionclientsdk2.encryption.providers.SymmetricStaticProvider;
import software.amazon.cryptools.dynamodbencryptionclientsdk2.internal.Utils;
import software.amazon.cryptools.dynamodbencryptionclientsdk2.testing.AttrMatcher;
import software.amazon.cryptools.dynamodbencryptionclientsdk2.testing.EncryptionTestHelper;
import software.amazon.cryptools.dynamodbencryptionclientsdk2.testing.TestDelegatedKey;

public class DelegatedEncryptionTest {
    private static SecretKeySpec rawEncryptionKey;
    private static SecretKeySpec rawMacKey;
    private static DelegatedKey encryptionKey;
    private static DelegatedKey macKey;
    
    private EncryptionMaterialsProvider prov;
    private DynamoDbEncryptor encryptor;
    private Map<String, AttributeValue> attribs;
    private EncryptionContext context;
    
    @BeforeClass
    public static void setupClass() {
        rawEncryptionKey = new SecretKeySpec(Utils.getRandom(32), "AES");
        encryptionKey = new TestDelegatedKey(rawEncryptionKey);
        
        rawMacKey = new SecretKeySpec(Utils.getRandom(32), "HmacSHA256");
        macKey = new TestDelegatedKey(rawMacKey);
    }
    
    @BeforeMethod
    public void setUp() {
        prov = new SymmetricStaticProvider(encryptionKey, macKey,
                Collections.emptyMap());
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
        Map<String, AttributeValue> encryptedAttributes = 
                EncryptionTestHelper.encryptAllFieldsExcept(encryptor, Collections.unmodifiableMap(attribs), context, asList("hashKey", "rangeKey", "version"));
        assertThat(encryptedAttributes, AttrMatcher.invert(attribs));
        Map<String, AttributeValue> decryptedAttributes =
                EncryptionTestHelper.decryptAllFieldsExcept(encryptor, Collections.unmodifiableMap(encryptedAttributes), context, asList("hashKey", "rangeKey", "version"));
        assertThat(decryptedAttributes, AttrMatcher.match(attribs));
        
        // Make sure keys and version are not encrypted
        assertAttrEquals(attribs.get("hashKey"), encryptedAttributes.get("hashKey"));
        assertAttrEquals(attribs.get("rangeKey"), encryptedAttributes.get("rangeKey"));
        assertAttrEquals(attribs.get("version"), encryptedAttributes.get("version"));
        
        // Make sure String has been encrypted (we'll assume the others are correct as well)
        assertTrue(encryptedAttributes.containsKey("stringValue"));
        assertNull(encryptedAttributes.get("stringValue").s());
        assertNotNull(encryptedAttributes.get("stringValue").b());
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
    
    @Test(expectedExceptions = IllegalArgumentException.class)
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
        prov = new SymmetricStaticProvider(null, macKey, Collections.emptyMap());
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
            new SymmetricStaticProvider(encryptionKey, sigPair, Collections.emptyMap()), "encryptor-");
        
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
            new SymmetricStaticProvider(encryptionKey, sigPair, Collections.emptyMap()), "encryptor-");
        
        Map<String, AttributeValue> encryptedAttributes = EncryptionTestHelper.encryptAllFieldsExcept(encryptor, attribs, context, attribs.keySet());
        assertThat(encryptedAttributes, AttrMatcher.invert(attribs));
        Map<String, AttributeValue> modifiedEncryptedAttributes = new HashMap<>(encryptedAttributes);
        modifiedEncryptedAttributes.put("hashKey", AttributeValue.builder().n("666").build());
        EncryptionTestHelper.decryptAllFieldsExcept(encryptor, modifiedEncryptedAttributes, context, attribs.keySet());
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

}
