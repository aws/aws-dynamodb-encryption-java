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
package com.amazonaws.services.dynamodbv2.datamodeling.encryption;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;

import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.SignatureException;
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
import org.junit.Assert;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import com.amazonaws.services.dynamodbv2.datamodeling.encryption.materials.DecryptionMaterials;
import com.amazonaws.services.dynamodbv2.datamodeling.encryption.materials.EncryptionMaterials;
import com.amazonaws.services.dynamodbv2.datamodeling.encryption.providers.EncryptionMaterialsProvider;
import com.amazonaws.services.dynamodbv2.datamodeling.encryption.providers.SymmetricStaticProvider;
import com.amazonaws.services.dynamodbv2.datamodeling.internal.Utils;
import com.amazonaws.services.dynamodbv2.model.AttributeValue;
import com.amazonaws.services.dynamodbv2.testing.AttrMatcher;

public class DynamoDBEncryptorTest {
    private static SecretKey encryptionKey;
    private static SecretKey macKey;
    
    private InstrumentedEncryptionMaterialsProvider prov;
    private DynamoDBEncryptor encryptor;
    private Map<String, AttributeValue> attribs;
    private EncryptionContext context;
    
    @BeforeClass
    public static void setUpClass() throws Exception {
        KeyGenerator aesGen = KeyGenerator.getInstance("AES");
        aesGen.init(128, Utils.getRng());
        encryptionKey = aesGen.generateKey();
        
        KeyGenerator macGen = KeyGenerator.getInstance("HmacSHA256");
        macGen.init(256, Utils.getRng());
        macKey = macGen.generateKey();
    }
    
    @Before
    public void setUp() throws Exception {
        prov = new InstrumentedEncryptionMaterialsProvider(
                    new SymmetricStaticProvider(encryptionKey, macKey,
                        Collections.<String, String> emptyMap()));
        encryptor = DynamoDBEncryptor.getInstance(prov, "encryptor-");
        
        attribs = new HashMap<String, AttributeValue>();
        attribs.put("intValue", new AttributeValue().withN("123"));
        attribs.put("stringValue", new AttributeValue().withS("Hello world!"));
        attribs.put("byteArrayValue", new AttributeValue().withB(ByteBuffer.wrap(new byte[] {0, 1, 2, 3, 4, 5})));
        attribs.put("stringSet", new AttributeValue().withSS("Goodbye", "Cruel", "World", "?"));
        attribs.put("intSet", new AttributeValue().withNS("1", "200", "10", "15", "0"));
        attribs.put("hashKey", new AttributeValue().withN("5"));
        attribs.put("rangeKey", new AttributeValue().withN("7"));
        attribs.put("version", new AttributeValue().withN("0"));

        context = new EncryptionContext.Builder()
            .withTableName("TableName")
            .withHashKeyName("hashKey")
            .withRangeKeyName("rangeKey")
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
    public void fullEncryption() throws GeneralSecurityException {
        Map<String, AttributeValue> encryptedAttributes = 
                encryptor.encryptAllFieldsExcept(Collections.unmodifiableMap(attribs), context, "hashKey", "rangeKey", "version");
        assertThat(encryptedAttributes, AttrMatcher.invert(attribs));

        Map<String, AttributeValue> decryptedAttributes =
                encryptor.decryptAllFieldsExcept(Collections.unmodifiableMap(encryptedAttributes), context, "hashKey", "rangeKey", "version");
        assertThat(decryptedAttributes, AttrMatcher.match(attribs));

        // Make sure keys and version are not encrypted
        assertAttrEquals(attribs.get("hashKey"), encryptedAttributes.get("hashKey"));
        assertAttrEquals(attribs.get("rangeKey"), encryptedAttributes.get("rangeKey"));
        assertAttrEquals(attribs.get("version"), encryptedAttributes.get("version"));

        // Make sure String has been encrypted (we'll assume the others are correct as well)
        assertTrue(encryptedAttributes.containsKey("stringValue"));
        assertNull(encryptedAttributes.get("stringValue").getS());
        assertNotNull(encryptedAttributes.get("stringValue").getB());

        // Make sure we're calling the proper getEncryptionMaterials method
        assertEquals("Wrong getEncryptionMaterials() called", 
                1, prov.getCallCount("getEncryptionMaterials(EncryptionContext context)"));
    }

    @Test
    public void ensureEncryptedAttributesUnmodified() throws GeneralSecurityException {
        Map<String, AttributeValue> encryptedAttributes =
                encryptor.encryptAllFieldsExcept(Collections.unmodifiableMap(attribs), context, "hashKey", "rangeKey", "version");
        String encryptedString = encryptedAttributes.toString();
        encryptor.decryptAllFieldsExcept(Collections.unmodifiableMap(encryptedAttributes), context, "hashKey", "rangeKey", "version");

        assertEquals(encryptedString, encryptedAttributes.toString());
    }

    @Test(expected=SignatureException.class)
    public void fullEncryptionBadSignature() throws GeneralSecurityException {
        Map<String, AttributeValue> encryptedAttributes =
                encryptor.encryptAllFieldsExcept(Collections.unmodifiableMap(attribs), context, "hashKey", "rangeKey", "version");
        assertThat(encryptedAttributes, AttrMatcher.invert(attribs));
        encryptedAttributes.get("hashKey").setN("666");
        encryptor.decryptAllFieldsExcept(Collections.unmodifiableMap(encryptedAttributes), context, "hashKey", "rangeKey", "version");
    }
    
    @Test(expected=IllegalArgumentException.class)
    public void badVersionNumber() throws GeneralSecurityException {
        Map<String, AttributeValue> encryptedAttributes =
                encryptor.encryptAllFieldsExcept(Collections.unmodifiableMap(attribs), context, "hashKey", "rangeKey", "version");
        ByteBuffer materialDescription = encryptedAttributes.get(encryptor.getMaterialDescriptionFieldName()).getB();
        byte[] rawArray = materialDescription.array();
        assertEquals(0, rawArray[0]); // This will need to be kept in sync with the current version.
        rawArray[0] = 100;
        encryptedAttributes.put(encryptor.getMaterialDescriptionFieldName(), new AttributeValue().withB(ByteBuffer.wrap(rawArray)));
        encryptor.decryptAllFieldsExcept(Collections.unmodifiableMap(encryptedAttributes), context, "hashKey", "rangeKey", "version");
    }
    
    @Test
    public void signedOnly() throws GeneralSecurityException {
        Map<String, AttributeValue> encryptedAttributes = 
                encryptor.encryptAllFieldsExcept(attribs, context, attribs.keySet().toArray(new String[0]));
        assertThat(encryptedAttributes, AttrMatcher.invert(attribs));
        Map<String, AttributeValue> decryptedAttributes =
                encryptor.decryptAllFieldsExcept(encryptedAttributes, context, attribs.keySet().toArray(new String[0]));
        assertThat(decryptedAttributes, AttrMatcher.match(attribs));
        
        // Make sure keys and version are not encrypted
        assertAttrEquals(attribs.get("hashKey"), encryptedAttributes.get("hashKey"));
        assertAttrEquals(attribs.get("rangeKey"), encryptedAttributes.get("rangeKey"));
        assertAttrEquals(attribs.get("version"), encryptedAttributes.get("version"));
        
        // Make sure String has not been encrypted (we'll assume the others are correct as well)
        assertAttrEquals(attribs.get("stringValue"), encryptedAttributes.get("stringValue"));
    }
    
    @Test
    public void signedOnlyNullCryptoKey() throws GeneralSecurityException {
        prov = new InstrumentedEncryptionMaterialsProvider(
                new SymmetricStaticProvider(null, macKey, Collections.<String, String>emptyMap()));
        encryptor = DynamoDBEncryptor.getInstance(prov, "encryptor-");
        Map<String, AttributeValue> encryptedAttributes = 
                encryptor.encryptAllFieldsExcept(attribs, context, attribs.keySet().toArray(new String[0]));
        assertThat(encryptedAttributes, AttrMatcher.invert(attribs));
        Map<String, AttributeValue> decryptedAttributes = encryptor.decryptAllFieldsExcept(encryptedAttributes, context, attribs.keySet().toArray(new String[0]));
        assertThat(decryptedAttributes, AttrMatcher.match(attribs));
        
        // Make sure keys and version are not encrypted
        assertAttrEquals(attribs.get("hashKey"), encryptedAttributes.get("hashKey"));
        assertAttrEquals(attribs.get("rangeKey"), encryptedAttributes.get("rangeKey"));
        assertAttrEquals(attribs.get("version"), encryptedAttributes.get("version"));
        
        // Make sure String has not been encrypted (we'll assume the others are correct as well)
        assertAttrEquals(attribs.get("stringValue"), encryptedAttributes.get("stringValue"));
    }
    
    @Test(expected=SignatureException.class)
    public void signedOnlyBadSignature() throws GeneralSecurityException {
        Map<String, AttributeValue> encryptedAttributes = 
                encryptor.encryptAllFieldsExcept(attribs, context, attribs.keySet().toArray(new String[0]));
        assertThat(encryptedAttributes, AttrMatcher.invert(attribs));
        encryptedAttributes.get("hashKey").setN("666");
        encryptor.decryptAllFieldsExcept(encryptedAttributes, context, attribs.keySet().toArray(new String[0]));
    }
    
    @Test(expected=SignatureException.class)
    public void signedOnlyNoSignature() throws GeneralSecurityException {
        Map<String, AttributeValue> encryptedAttributes = 
                encryptor.encryptAllFieldsExcept(attribs, context, attribs.keySet().toArray(new String[0]));
        assertThat(encryptedAttributes, AttrMatcher.invert(attribs));
        encryptedAttributes.remove(encryptor.getSignatureFieldName());
        encryptor.decryptAllFieldsExcept(encryptedAttributes, context, attribs.keySet().toArray(new String[0]));
    }
    
    @Test
    public void RsaSignedOnly() throws GeneralSecurityException {
        KeyPairGenerator rsaGen = KeyPairGenerator.getInstance("RSA");
        rsaGen.initialize(2048, Utils.getRng());
        KeyPair sigPair = rsaGen.generateKeyPair();
        encryptor = DynamoDBEncryptor.getInstance(
                new SymmetricStaticProvider(encryptionKey, sigPair, 
                    Collections.<String, String> emptyMap()), "encryptor-");
        
        Map<String, AttributeValue> encryptedAttributes = encryptor.encryptAllFieldsExcept(attribs, context, attribs.keySet().toArray(new String[0]));
        assertThat(encryptedAttributes, AttrMatcher.invert(attribs));
        Map<String, AttributeValue> decryptedAttributes = 
                encryptor.decryptAllFieldsExcept(encryptedAttributes, context, attribs.keySet().toArray(new String[0]));
        assertThat(decryptedAttributes, AttrMatcher.match(attribs));
        
        // Make sure keys and version are not encrypted
        assertAttrEquals(attribs.get("hashKey"), encryptedAttributes.get("hashKey"));
        assertAttrEquals(attribs.get("rangeKey"), encryptedAttributes.get("rangeKey"));
        assertAttrEquals(attribs.get("version"), encryptedAttributes.get("version"));
        
        // Make sure String has not been encrypted (we'll assume the others are correct as well)
        assertAttrEquals(attribs.get("stringValue"), encryptedAttributes.get("stringValue"));
    }
    
    @Test(expected=SignatureException.class)
    public void RsaSignedOnlyBadSignature() throws GeneralSecurityException {
        KeyPairGenerator rsaGen = KeyPairGenerator.getInstance("RSA");
        rsaGen.initialize(2048, Utils.getRng());
        KeyPair sigPair = rsaGen.generateKeyPair();
        encryptor = DynamoDBEncryptor.getInstance(
                new SymmetricStaticProvider(encryptionKey, sigPair, 
                    Collections.<String, String> emptyMap()), "encryptor-");
        
        Map<String, AttributeValue> encryptedAttributes = encryptor.encryptAllFieldsExcept(attribs, context, attribs.keySet().toArray(new String[0]));
        assertThat(encryptedAttributes, AttrMatcher.invert(attribs));
        encryptedAttributes.get("hashKey").setN("666");
        encryptor.decryptAllFieldsExcept(encryptedAttributes, context, attribs.keySet().toArray(new String[0]));
    }
    
    @Test
    public void EcdsaSignedOnly() throws GeneralSecurityException {

        encryptor = DynamoDBEncryptor.getInstance(getMaterialProviderwithECDSA());
        
        Map<String, AttributeValue> encryptedAttributes = encryptor.encryptAllFieldsExcept(attribs, context, attribs.keySet().toArray(new String[0]));
        assertThat(encryptedAttributes, AttrMatcher.invert(attribs));
        Map<String, AttributeValue> decryptedAttributes = 
                encryptor.decryptAllFieldsExcept(encryptedAttributes, context, attribs.keySet().toArray(new String[0]));
        assertThat(decryptedAttributes, AttrMatcher.match(attribs));
        
        // Make sure keys and version are not encrypted
        assertAttrEquals(attribs.get("hashKey"), encryptedAttributes.get("hashKey"));
        assertAttrEquals(attribs.get("rangeKey"), encryptedAttributes.get("rangeKey"));
        assertAttrEquals(attribs.get("version"), encryptedAttributes.get("version"));
        
        // Make sure String has not been encrypted (we'll assume the others are correct as well)
        assertAttrEquals(attribs.get("stringValue"), encryptedAttributes.get("stringValue"));
    }
    
    @Test(expected=SignatureException.class)
    public void EcdsaSignedOnlyBadSignature() throws GeneralSecurityException {

        encryptor = DynamoDBEncryptor.getInstance(getMaterialProviderwithECDSA());

        Map<String, AttributeValue> encryptedAttributes = encryptor.encryptAllFieldsExcept(attribs, context, attribs.keySet().toArray(new String[0]));
        assertThat(encryptedAttributes, AttrMatcher.invert(attribs));
        encryptedAttributes.get("hashKey").setN("666");
        encryptor.decryptAllFieldsExcept(encryptedAttributes, context, attribs.keySet().toArray(new String[0]));
    }

    private void assertAttrEquals(AttributeValue o1, AttributeValue o2) {
        Assert.assertEquals(o1.getB(), o2.getB());
        assertSetsEqual(o1.getBS(), o2.getBS());
        Assert.assertEquals(o1.getN(), o2.getN());
        assertSetsEqual(o1.getNS(), o2.getNS());
        Assert.assertEquals(o1.getS(), o2.getS());
        assertSetsEqual(o1.getSS(), o2.getSS());
    }
    
    private <T> void assertSetsEqual(Collection<T> c1, Collection<T> c2) {
        Assert.assertFalse(c1 == null ^ c2 == null);
        if (c1 != null) {
            Set<T> s1 = new HashSet<T>(c1);
            Set<T> s2 = new HashSet<T>(c2);
            Assert.assertEquals(s1, s2);
        }
    }

    private EncryptionMaterialsProvider getMaterialProviderwithECDSA() 
           throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, NoSuchProviderException {
            Security.addProvider(new BouncyCastleProvider());
            ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("secp384r1");
            KeyPairGenerator g = KeyPairGenerator.getInstance("ECDSA", "BC");
            g.initialize(ecSpec, Utils.getRng());
            KeyPair keypair = g.generateKeyPair();
            Map<String, String> description = new HashMap<String, String>();
            description.put(DynamoDBEncryptor.DEFAULT_SIGNING_ALGORITHM_HEADER, "SHA384withECDSA");
            return new SymmetricStaticProvider(null, keypair, description);
    }

    private static final class InstrumentedEncryptionMaterialsProvider implements EncryptionMaterialsProvider {
        private final EncryptionMaterialsProvider delegate;
        private final ConcurrentHashMap<String, AtomicInteger> calls = new ConcurrentHashMap<>();
        
        public InstrumentedEncryptionMaterialsProvider(EncryptionMaterialsProvider delegate) {
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
        
        public int getCallCount(String method) {
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
