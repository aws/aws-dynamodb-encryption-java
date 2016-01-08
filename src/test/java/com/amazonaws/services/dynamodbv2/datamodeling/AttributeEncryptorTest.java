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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;

import java.nio.ByteBuffer;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import org.junit.Assert;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import com.amazonaws.services.dynamodbv2.datamodeling.AttributeTransformer.Parameters;
import com.amazonaws.services.dynamodbv2.datamodeling.encryption.providers.EncryptionMaterialsProvider;
import com.amazonaws.services.dynamodbv2.datamodeling.encryption.providers.SymmetricStaticProvider;
import com.amazonaws.services.dynamodbv2.model.AttributeValue;
import com.amazonaws.services.dynamodbv2.testing.AttrMatcher;
import com.amazonaws.services.dynamodbv2.testing.FakeParameters;
import com.amazonaws.services.dynamodbv2.testing.types.BaseClass;
import com.amazonaws.services.dynamodbv2.testing.types.Mixed;
import com.amazonaws.services.dynamodbv2.testing.types.SignOnly;
import com.amazonaws.services.dynamodbv2.testing.types.Untouched;

public class AttributeEncryptorTest {
    private static final String RANGE_KEY = "rangeKey";
    private static final String HASH_KEY = "hashKey";
    private static final String TABLE_NAME = "TableName";
    private static SecureRandom rnd;
    private static SecretKey encryptionKey;
    private static SecretKey macKey;

    private EncryptionMaterialsProvider prov;
    private AttributeEncryptor encryptor;
    private Map<String, AttributeValue> attribs;

    @BeforeClass
    public static void setUpClass() throws Exception {
        rnd = new SecureRandom();
        KeyGenerator aesGen = KeyGenerator.getInstance("AES");
        aesGen.init(128, rnd);
        encryptionKey = aesGen.generateKey();

        KeyGenerator macGen = KeyGenerator.getInstance("HmacSHA256");
        macGen.init(256, rnd);
        macKey = macGen.generateKey();
    }

    @Before
    public void setUp() throws Exception {
        prov = new SymmetricStaticProvider(encryptionKey, macKey,
                Collections.<String, String> emptyMap());
        encryptor = new AttributeEncryptor(prov);

        attribs = new HashMap<String, AttributeValue>();
        attribs.put("intValue", new AttributeValue().withN("123"));
        attribs.put("stringValue", new AttributeValue().withS("Hello world!"));
        attribs.put("byteArrayValue",
                new AttributeValue().withB(ByteBuffer.wrap(new byte[] { 0, 1, 2, 3, 4, 5 })));
        attribs.put("stringSet", new AttributeValue().withSS("Goodbye", "Cruel", "World", "?"));
        attribs.put("intSet", new AttributeValue().withNS("1", "200", "10", "15", "0"));
        attribs.put(HASH_KEY, new AttributeValue().withN("5"));
        attribs.put(RANGE_KEY, new AttributeValue().withN("7"));
        attribs.put("version", new AttributeValue().withN("0"));
        Map<String, AttributeValue> map = new HashMap<>();
        map.put("key1", new AttributeValue().withS("value1"));
        map.put("key2", new AttributeValue().withS("value2"));
        attribs.put("mapValue", new AttributeValue().withM(map));
    }

    @Test
    public void testUnaffected() {
        Parameters<Untouched> params = FakeParameters.getInstance(Untouched.class, attribs, null,
                TABLE_NAME, HASH_KEY, RANGE_KEY);
        Map<String, AttributeValue> encryptedAttributes = encryptor.transform(params);
        assertEquals(attribs, encryptedAttributes);
    }

    @Test
    public void fullEncryption() {
        Parameters<BaseClass> params = FakeParameters.getInstance(BaseClass.class, attribs, null,
                TABLE_NAME, HASH_KEY, RANGE_KEY);
        Map<String, AttributeValue> encryptedAttributes = encryptor.transform(params);
        assertThat(encryptedAttributes, AttrMatcher.invert(attribs));
        params = FakeParameters.getInstance(BaseClass.class, encryptedAttributes, null, TABLE_NAME,
                HASH_KEY, RANGE_KEY);

        // Make sure keys and version are not encrypted
        assertAttrEquals(attribs.get(HASH_KEY), encryptedAttributes.get(HASH_KEY));
        assertAttrEquals(attribs.get(RANGE_KEY), encryptedAttributes.get(RANGE_KEY));
        assertAttrEquals(attribs.get("version"), encryptedAttributes.get("version"));

        // Make sure String has been encrypted (we'll assume the others are correct as well)
        assertTrue(encryptedAttributes.containsKey("stringValue"));
        assertNull(encryptedAttributes.get("stringValue").getS());
        assertNotNull(encryptedAttributes.get("stringValue").getB());
        assertNull(encryptedAttributes.get("mapValue").getM().get("key1").getS());
        assertNull(encryptedAttributes.get("mapValue").getM().get("key2").getS());
        assertNotNull(encryptedAttributes.get("mapValue").getM().get("key1").getB());
        assertNotNull(encryptedAttributes.get("mapValue").getM().get("key2").getB());

        Map<String, AttributeValue> decryptedAttributes = encryptor.untransform(params);
        assertThat(decryptedAttributes, AttrMatcher.match(attribs));
    }

    @Test(expected = DynamoDBMappingException.class)
    public void fullEncryptionBadSignature() {
        Parameters<BaseClass> params = FakeParameters.getInstance(BaseClass.class, attribs, null,
                TABLE_NAME, HASH_KEY, RANGE_KEY);
        Map<String, AttributeValue> encryptedAttributes = encryptor.transform(params);
        assertThat(encryptedAttributes, AttrMatcher.invert(attribs));
        encryptedAttributes.get(HASH_KEY).setN("666");
        params = FakeParameters.getInstance(BaseClass.class, encryptedAttributes, null, TABLE_NAME,
                HASH_KEY, RANGE_KEY);
        encryptor.untransform(params);
    }

    @Test(expected = DynamoDBMappingException.class)
    public void badVersionNumber() {
        Parameters<BaseClass> params = FakeParameters.getInstance(BaseClass.class, attribs, null,
                TABLE_NAME, HASH_KEY, RANGE_KEY);
        Map<String, AttributeValue> encryptedAttributes = encryptor.transform(params);
        ByteBuffer materialDescription = encryptedAttributes.get(
                encryptor.getEncryptor().getMaterialDescriptionFieldName()).getB();
        byte[] rawArray = materialDescription.array();
        assertEquals(0, rawArray[0]); // This will need to be kept in sync with the current version.
        rawArray[0] = 100;
        encryptedAttributes.put(encryptor.getEncryptor().getMaterialDescriptionFieldName(),
                new AttributeValue().withB(ByteBuffer.wrap(rawArray)));
        params = FakeParameters.getInstance(BaseClass.class, encryptedAttributes, null, TABLE_NAME,
                HASH_KEY, RANGE_KEY);
        encryptor.untransform(params);
    }

    @Test
    public void signedOnly() {
        Parameters<SignOnly> params = FakeParameters.getInstance(SignOnly.class, attribs, null,
                TABLE_NAME, HASH_KEY, RANGE_KEY);
        Map<String, AttributeValue> encryptedAttributes = encryptor.transform(params);
        assertThat(encryptedAttributes, AttrMatcher.invert(attribs));
        params = FakeParameters.getInstance(SignOnly.class, encryptedAttributes, null, TABLE_NAME,
                HASH_KEY, RANGE_KEY);
        Map<String, AttributeValue> decryptedAttributes = encryptor.untransform(params);
        assertThat(decryptedAttributes, AttrMatcher.match(attribs));

        // Make sure keys and version are not encrypted
        assertAttrEquals(attribs.get(HASH_KEY), encryptedAttributes.get(HASH_KEY));
        assertAttrEquals(attribs.get(RANGE_KEY), encryptedAttributes.get(RANGE_KEY));
        assertAttrEquals(attribs.get("version"), encryptedAttributes.get("version"));

        // Make sure String has not been encrypted (we'll assume the others are correct as well)
        assertAttrEquals(attribs.get("stringValue"), encryptedAttributes.get("stringValue"));

        assertEquals(encryptedAttributes.get("mapValue").getM().get("key1").getS(), "value1");
        assertEquals(encryptedAttributes.get("mapValue").getM().get("key2").getS(), "value2");
    }

    @Test
    public void signedOnlyNullCryptoKey() {
        prov = new SymmetricStaticProvider(null, macKey, Collections.<String, String> emptyMap());
        encryptor = new AttributeEncryptor(prov);
        Parameters<SignOnly> params = FakeParameters.getInstance(SignOnly.class, attribs, null,
                TABLE_NAME, HASH_KEY, RANGE_KEY);
        Map<String, AttributeValue> encryptedAttributes = encryptor.transform(params);
        assertThat(encryptedAttributes, AttrMatcher.invert(attribs));
        params = FakeParameters.getInstance(SignOnly.class, encryptedAttributes, null, TABLE_NAME,
                HASH_KEY, RANGE_KEY);
        Map<String, AttributeValue> decryptedAttributes = encryptor.untransform(params);
        assertThat(decryptedAttributes, AttrMatcher.match(attribs));

        // Make sure keys and version are not encrypted
        assertAttrEquals(attribs.get(HASH_KEY), encryptedAttributes.get(HASH_KEY));
        assertAttrEquals(attribs.get(RANGE_KEY), encryptedAttributes.get(RANGE_KEY));
        assertAttrEquals(attribs.get("version"), encryptedAttributes.get("version"));

        // Make sure String has not been encrypted (we'll assume the others are correct as well)
        assertAttrEquals(attribs.get("stringValue"), encryptedAttributes.get("stringValue"));

        assertEquals(encryptedAttributes.get("mapValue").getM().get("key1").getS(), "value1");
        assertEquals(encryptedAttributes.get("mapValue").getM().get("key2").getS(), "value2");
    }

    @Test(expected = DynamoDBMappingException.class)
    public void signedOnlyBadSignature() {
        Parameters<SignOnly> params = FakeParameters.getInstance(SignOnly.class, attribs, null,
                TABLE_NAME, HASH_KEY, RANGE_KEY);
        Map<String, AttributeValue> encryptedAttributes = encryptor.transform(params);
        assertThat(encryptedAttributes, AttrMatcher.invert(attribs));
        encryptedAttributes.get(HASH_KEY).setN("666");
        params = FakeParameters.getInstance(SignOnly.class, encryptedAttributes, null, TABLE_NAME,
                HASH_KEY, RANGE_KEY);
        encryptor.untransform(params);
    }

    @Test(expected = DynamoDBMappingException.class)
    public void signedOnlyNoSignature() {
        Parameters<SignOnly> params = FakeParameters.getInstance(SignOnly.class, attribs, null,
                TABLE_NAME, HASH_KEY, RANGE_KEY);
        Map<String, AttributeValue> encryptedAttributes = encryptor.transform(params);
        assertThat(encryptedAttributes, AttrMatcher.invert(attribs));
        encryptedAttributes.remove(encryptor.getEncryptor().getSignatureFieldName());
        encryptor.untransform(params);
    }

    @Test
    public void RsaSignedOnly() throws NoSuchAlgorithmException {
        KeyPairGenerator rsaGen = KeyPairGenerator.getInstance("RSA");
        rsaGen.initialize(2048, rnd);
        KeyPair sigPair = rsaGen.generateKeyPair();
        encryptor = new AttributeEncryptor(new SymmetricStaticProvider(encryptionKey, sigPair,
                Collections.<String, String> emptyMap()));

        Parameters<SignOnly> params = FakeParameters.getInstance(SignOnly.class, attribs, null,
                TABLE_NAME, HASH_KEY, RANGE_KEY);
        Map<String, AttributeValue> encryptedAttributes = encryptor.transform(params);
        assertThat(encryptedAttributes, AttrMatcher.invert(attribs));
        params = FakeParameters.getInstance(SignOnly.class, encryptedAttributes, null, TABLE_NAME,
                HASH_KEY, RANGE_KEY);
        Map<String, AttributeValue> decryptedAttributes = encryptor.untransform(params);
        assertThat(decryptedAttributes, AttrMatcher.match(attribs));

        // Make sure keys and version are not encrypted
        assertAttrEquals(attribs.get(HASH_KEY), encryptedAttributes.get(HASH_KEY));
        assertAttrEquals(attribs.get(RANGE_KEY), encryptedAttributes.get(RANGE_KEY));
        assertAttrEquals(attribs.get("version"), encryptedAttributes.get("version"));

        // Make sure String has not been encrypted (we'll assume the others are correct as well)
        assertAttrEquals(attribs.get("stringValue"), encryptedAttributes.get("stringValue"));

        assertEquals(encryptedAttributes.get("mapValue").getM().get("key1").getS(), "value1");
        assertEquals(encryptedAttributes.get("mapValue").getM().get("key2").getS(), "value2");
    }

    @Test(expected = DynamoDBMappingException.class)
    public void RsaSignedOnlyBadSignature() throws NoSuchAlgorithmException {
        KeyPairGenerator rsaGen = KeyPairGenerator.getInstance("RSA");
        rsaGen.initialize(2048, rnd);
        KeyPair sigPair = rsaGen.generateKeyPair();
        encryptor = new AttributeEncryptor(new SymmetricStaticProvider(encryptionKey, sigPair,
                Collections.<String, String> emptyMap()));
        Parameters<SignOnly> params = FakeParameters.getInstance(SignOnly.class, attribs, null,
                TABLE_NAME, HASH_KEY, RANGE_KEY);
        Map<String, AttributeValue> encryptedAttributes = encryptor.transform(params);
        assertThat(encryptedAttributes, AttrMatcher.invert(attribs));
        encryptedAttributes.get(HASH_KEY).setN("666");
        params = FakeParameters.getInstance(SignOnly.class, encryptedAttributes, null, TABLE_NAME,
                HASH_KEY, RANGE_KEY);
        encryptor.untransform(params);
    }

    @Test
    public void mixed() {
        Parameters<Mixed> params = FakeParameters.getInstance(Mixed.class, attribs, null,
                TABLE_NAME, HASH_KEY, RANGE_KEY);
        Map<String, AttributeValue> encryptedAttributes = encryptor.transform(params);
        assertThat(encryptedAttributes, AttrMatcher.invert(attribs));
        params = FakeParameters.getInstance(Mixed.class, encryptedAttributes, null, TABLE_NAME,
                HASH_KEY, RANGE_KEY);

        // Make sure keys and version are not encrypted
        assertAttrEquals(attribs.get(HASH_KEY), encryptedAttributes.get(HASH_KEY));
        assertAttrEquals(attribs.get(RANGE_KEY), encryptedAttributes.get(RANGE_KEY));
        assertAttrEquals(attribs.get("version"), encryptedAttributes.get("version"));

        // Make sure StringSet has been encrypted (we'll assume the others are correct as well)
        assertTrue(encryptedAttributes.containsKey("stringSet"));
        assertNull(encryptedAttributes.get("stringSet").getSS());
        assertNotNull(encryptedAttributes.get("stringSet").getB());
        assertNull(encryptedAttributes.get("mapValue").getM().get("key1").getS());
        assertNull(encryptedAttributes.get("mapValue").getM().get("key2").getS());
        assertNotNull(encryptedAttributes.get("mapValue").getM().get("key1").getB());
        assertNotNull(encryptedAttributes.get("mapValue").getM().get("key2").getB());

        // Test those not encrypted
        assertAttrEquals(attribs.get("stringValue"), encryptedAttributes.get("stringValue"));
        assertAttrEquals(attribs.get("intValue"), encryptedAttributes.get("intValue"));

        // intValue is not signed, make sure we can modify it and still decrypt
        encryptedAttributes.get("intValue").setN("666");

        params = FakeParameters.getInstance(Mixed.class, encryptedAttributes, null, TABLE_NAME,
                HASH_KEY, RANGE_KEY);
        Map<String, AttributeValue> decryptedAttributes = encryptor.untransform(params);
        assertThat(decryptedAttributes, AttrMatcher.match(attribs));
    }

    @Test(expected = DynamoDBMappingException.class)
    public void mixedBadSignature() {
        Parameters<Mixed> params = FakeParameters.getInstance(Mixed.class, attribs, null,
                TABLE_NAME, HASH_KEY, RANGE_KEY);
        Map<String, AttributeValue> encryptedAttributes = encryptor.transform(params);
        assertThat(encryptedAttributes, AttrMatcher.invert(attribs));
        encryptedAttributes.get("stringValue").setS("666");
        params = FakeParameters.getInstance(Mixed.class, encryptedAttributes, null, TABLE_NAME,
                HASH_KEY, RANGE_KEY);
        encryptor.untransform(params);
    }

    private void assertAttrEquals(AttributeValue o1, AttributeValue o2) {
        Assert.assertEquals(o1.getB(), o2.getB());
        assertSetsEqual(o1.getBS(), o2.getBS());
        Assert.assertEquals(o1.getN(), o2.getN());
        assertSetsEqual(o1.getNS(), o2.getNS());
        Assert.assertEquals(o1.getS(), o2.getS());
        assertSetsEqual(o1.getSS(), o2.getSS());
        Assert.assertEquals(o1.getM(), o2.getM());
    }

    private <T> void assertSetsEqual(Collection<T> c1, Collection<T> c2) {
        Assert.assertFalse(c1 == null ^ c2 == null);
        if (c1 != null) {
            Set<T> s1 = new HashSet<T>(c1);
            Set<T> s2 = new HashSet<T>(c2);
            Assert.assertEquals(s1, s2);
        }
    }
}
