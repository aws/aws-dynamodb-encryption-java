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

import com.amazonaws.services.dynamodbv2.datamodeling.AttributeTransformer.Parameters;
import com.amazonaws.services.dynamodbv2.datamodeling.encryption.providers.EncryptionMaterialsProvider;
import com.amazonaws.services.dynamodbv2.datamodeling.encryption.providers.SymmetricStaticProvider;
import com.amazonaws.services.dynamodbv2.datamodeling.internal.Utils;
import com.amazonaws.services.dynamodbv2.model.AttributeValue;
import com.amazonaws.services.dynamodbv2.testing.AttrMatcher;
import com.amazonaws.services.dynamodbv2.testing.FakeParameters;
import com.amazonaws.services.dynamodbv2.testing.types.BaseClass;
import com.amazonaws.services.dynamodbv2.testing.types.BaseClassWithNewAttribute;
import com.amazonaws.services.dynamodbv2.testing.types.BaseClassWithUnknownAttributeAnnotation;
import com.amazonaws.services.dynamodbv2.testing.types.DoNotEncryptField;
import com.amazonaws.services.dynamodbv2.testing.types.DoNotTouchField;
import com.amazonaws.services.dynamodbv2.testing.types.Mixed;
import com.amazonaws.services.dynamodbv2.testing.types.SignOnly;
import com.amazonaws.services.dynamodbv2.testing.types.SignOnlyWithUnknownAttributeAnnotation;
import com.amazonaws.services.dynamodbv2.testing.types.SignOnlyWithUnknownAttributeAnnotationWithNewAttribute;
import com.amazonaws.services.dynamodbv2.testing.types.TableOverride;
import com.amazonaws.services.dynamodbv2.testing.types.Untouched;
import com.amazonaws.services.dynamodbv2.testing.types.UntouchedWithNewAttribute;
import com.amazonaws.services.dynamodbv2.testing.types.UntouchedWithUnknownAttributeAnnotation;
import com.amazonaws.services.dynamodbv2.testing.types.UntouchedWithUnknownAttributeAnnotationWithNewAttribute;
import org.testng.Assert;
import org.testng.AssertJUnit;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.nio.ByteBuffer;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import static org.testng.AssertJUnit.assertEquals;
import static org.testng.AssertJUnit.assertNotNull;
import static org.testng.AssertJUnit.assertNull;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.testng.AssertJUnit.assertTrue;

public class AttributeEncryptorTest {
    private static final String RANGE_KEY = "rangeKey";
    private static final String HASH_KEY = "hashKey";
    private static final String TABLE_NAME = "TableName";
    private static SecretKey encryptionKey;
    private static SecretKey macKey;

    private EncryptionMaterialsProvider prov;
    private AttributeEncryptor encryptor;
    private Map<String, AttributeValue> attribs;

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
    public void setUp() throws Exception {
        prov = new SymmetricStaticProvider(encryptionKey, macKey,
                Collections.<String, String>emptyMap());
        encryptor = new AttributeEncryptor(prov);

        attribs = new HashMap<String, AttributeValue>();
        attribs.put("intValue", new AttributeValue().withN("123"));
        attribs.put("stringValue", new AttributeValue().withS("Hello world!"));
        attribs.put("byteArrayValue",
                new AttributeValue().withB(ByteBuffer.wrap(new byte[]{0, 1, 2, 3, 4, 5})));
        attribs.put("stringSet", new AttributeValue().withSS("Goodbye", "Cruel", "World", "?"));
        attribs.put("intSet", new AttributeValue().withNS("1", "200", "10", "15", "0"));
        attribs.put(HASH_KEY, new AttributeValue().withN("5"));
        attribs.put(RANGE_KEY, new AttributeValue().withN("7"));
        attribs.put("version", new AttributeValue().withN("0"));
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
        Map<String, AttributeValue> decryptedAttributes = encryptor.untransform(params);
        assertThat(decryptedAttributes, AttrMatcher.match(attribs));

        // Make sure keys and version are not encrypted
        assertAttrEquals(attribs.get(HASH_KEY), encryptedAttributes.get(HASH_KEY));
        assertAttrEquals(attribs.get(RANGE_KEY), encryptedAttributes.get(RANGE_KEY));
        assertAttrEquals(attribs.get("version"), encryptedAttributes.get("version"));

        // Make sure String has been encrypted (we'll assume the others are correct as well)
        assertTrue(encryptedAttributes.containsKey("stringValue"));
        assertNull(encryptedAttributes.get("stringValue").getS());
        assertNotNull(encryptedAttributes.get("stringValue").getB());
    }

    @Test(expectedExceptions = DynamoDBMappingException.class)
    public void rejectsPartialUpdate() {
        Parameters<BaseClass> params = FakeParameters.getInstance(BaseClass.class, attribs, null,
                TABLE_NAME, HASH_KEY, RANGE_KEY, true);
        encryptor.transform(params);
    }

    @Test(expectedExceptions = DynamoDBMappingException.class)
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

    @Test(expectedExceptions = DynamoDBMappingException.class)
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
    }

    @Test
    public void signedOnlyNullCryptoKey() {
        prov = new SymmetricStaticProvider(null, macKey, Collections.<String, String>emptyMap());
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
    }

    @Test(expectedExceptions = DynamoDBMappingException.class)
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

    @Test(expectedExceptions = DynamoDBMappingException.class)
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
        rsaGen.initialize(2048, Utils.getRng());
        KeyPair sigPair = rsaGen.generateKeyPair();
        encryptor = new AttributeEncryptor(new SymmetricStaticProvider(encryptionKey, sigPair,
                Collections.<String, String>emptyMap()));

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
    }

    @Test(expectedExceptions = DynamoDBMappingException.class)
    public void RsaSignedOnlyBadSignature() throws NoSuchAlgorithmException {
        KeyPairGenerator rsaGen = KeyPairGenerator.getInstance("RSA");
        rsaGen.initialize(2048, Utils.getRng());
        KeyPair sigPair = rsaGen.generateKeyPair();
        encryptor = new AttributeEncryptor(new SymmetricStaticProvider(encryptionKey, sigPair,
                Collections.<String, String>emptyMap()));
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
        Map<String, AttributeValue> decryptedAttributes = encryptor.untransform(params);
        assertThat(decryptedAttributes, AttrMatcher.match(attribs));

        // Make sure keys and version are not encrypted
        assertAttrEquals(attribs.get(HASH_KEY), encryptedAttributes.get(HASH_KEY));
        assertAttrEquals(attribs.get(RANGE_KEY), encryptedAttributes.get(RANGE_KEY));
        assertAttrEquals(attribs.get("version"), encryptedAttributes.get("version"));

        // Make sure StringSet has been encrypted (we'll assume the others are correct as well)
        assertTrue(encryptedAttributes.containsKey("stringSet"));
        assertNull(encryptedAttributes.get("stringSet").getSS());
        assertNotNull(encryptedAttributes.get("stringSet").getB());

        // Test those not encrypted
        assertAttrEquals(attribs.get("stringValue"), encryptedAttributes.get("stringValue"));
        assertAttrEquals(attribs.get("intValue"), encryptedAttributes.get("intValue"));

        // intValue is not signed, make sure we can modify it and still decrypt
        encryptedAttributes.get("intValue").setN("666");

        params = FakeParameters.getInstance(Mixed.class, encryptedAttributes, null, TABLE_NAME,
                HASH_KEY, RANGE_KEY);
        decryptedAttributes = encryptor.untransform(params);
        assertThat(decryptedAttributes, AttrMatcher.match(attribs));
    }

    @Test(expectedExceptions = DynamoDBMappingException.class)
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

    @Test(expectedExceptions = DynamoDBMappingException.class)
    public void tableNameRespected() {
        Parameters<BaseClass> params = FakeParameters.getInstance(BaseClass.class, attribs, null, "firstTable",
                HASH_KEY, RANGE_KEY);
        Map<String, AttributeValue> encryptedAttributes = encryptor.transform(params);
        assertThat(encryptedAttributes, AttrMatcher.invert(attribs));
        params = FakeParameters.getInstance(BaseClass.class, encryptedAttributes, null, "secondTable",
                HASH_KEY, RANGE_KEY);
        encryptor.untransform(params);
    }

    @Test
    public void tableNameOverridden() {
        Parameters<TableOverride> params = FakeParameters.getInstance(TableOverride.class, attribs, null, "firstTable",
                HASH_KEY, RANGE_KEY);
        Map<String, AttributeValue> encryptedAttributes = encryptor.transform(params);
        assertThat(encryptedAttributes, AttrMatcher.invert(attribs));
        params = FakeParameters.getInstance(TableOverride.class, encryptedAttributes, null, "secondTable",
                HASH_KEY, RANGE_KEY);
        encryptor.untransform(params);
        Map<String, AttributeValue> decryptedAttributes = encryptor.untransform(params);
        assertThat(decryptedAttributes, AttrMatcher.match(attribs));
    }

    @Test(expectedExceptions = DynamoDBMappingException.class)
    public void testUnknownAttributeFails() {
        Map<String, AttributeValue> attributes = new HashMap<>(attribs);
        attributes.put("newAttribute", new AttributeValue().withS("foobar"));
        Parameters<? extends BaseClass> params = FakeParameters.getInstance(
                BaseClassWithNewAttribute.class, attributes, null,
                TABLE_NAME, HASH_KEY, RANGE_KEY);
        Map<String, AttributeValue> encryptedAttributes = encryptor.transform(params);
        assertThat(encryptedAttributes, AttrMatcher.invert(attributes));
        params = FakeParameters.getInstance(BaseClass.class, encryptedAttributes, null,
                TABLE_NAME, HASH_KEY, RANGE_KEY);
        encryptor.untransform(params);
    }

    @Test
    public void testUntouchedWithUnknownAttribute() {
        Map<String, AttributeValue> attributes = new HashMap<>(attribs);
        attributes.put("newAttribute", new AttributeValue().withS("foobar"));
        Parameters<? extends Untouched> params = FakeParameters.getInstance(
                UntouchedWithNewAttribute.class, attributes, null,
                TABLE_NAME, HASH_KEY, RANGE_KEY);
        Map<String, AttributeValue> encryptedAttributes = encryptor.transform(params);
        assertThat(encryptedAttributes, AttrMatcher.match(attributes));
        params = FakeParameters.getInstance(Untouched.class, encryptedAttributes, null,
                TABLE_NAME, HASH_KEY, RANGE_KEY);
        Map<String, AttributeValue> decryptedAttributes = encryptor.untransform(params);
        assertThat(decryptedAttributes, AttrMatcher.match(attributes));
    }

    @Test
    public void testUntouchedWithUnknownAttributeAnnotation() {
        Map<String, AttributeValue> attributes = new HashMap<>(attribs);
        attributes.put("newAttribute", new AttributeValue().withS("foobar"));
        Parameters<? extends UntouchedWithUnknownAttributeAnnotation> params = FakeParameters.getInstance(
                UntouchedWithUnknownAttributeAnnotationWithNewAttribute.class, attributes, null,
                TABLE_NAME, HASH_KEY, RANGE_KEY);
        Map<String, AttributeValue> encryptedAttributes = encryptor.transform(params);
        assertThat(encryptedAttributes, AttrMatcher.match(attributes));
        params = FakeParameters.getInstance(
                UntouchedWithUnknownAttributeAnnotation.class, encryptedAttributes, null,
                TABLE_NAME, HASH_KEY, RANGE_KEY);
        Map<String, AttributeValue> decryptedAttributes = encryptor.untransform(params);
        assertThat(decryptedAttributes, AttrMatcher.match(attributes));
    }

    @Test
    public void testSignOnlyWithUnknownAttributeAnnotation() {
        Map<String, AttributeValue> attributes = new HashMap<>(attribs);
        attributes.put("newAttribute", new AttributeValue().withS("foobar"));
        Parameters<? extends SignOnlyWithUnknownAttributeAnnotation> params = FakeParameters.getInstance(
                SignOnlyWithUnknownAttributeAnnotationWithNewAttribute.class, attributes, null,
                TABLE_NAME, HASH_KEY, RANGE_KEY);
        Map<String, AttributeValue> encryptedAttributes = encryptor.transform(params);
        assertThat(encryptedAttributes, AttrMatcher.invert(attributes));
        assertAttrEquals(new AttributeValue().withS("foobar"), encryptedAttributes.get("newAttribute"));
        params = FakeParameters.getInstance(
                SignOnlyWithUnknownAttributeAnnotation.class, encryptedAttributes, null,
                TABLE_NAME, HASH_KEY, RANGE_KEY);
        Map<String, AttributeValue> decryptedAttributes = encryptor.untransform(params);
        assertThat(decryptedAttributes, AttrMatcher.match(attributes));
    }

    @Test(expectedExceptions = DynamoDBMappingException.class)
    public void testSignOnlyWithUnknownAttributeAnnotationBadSignature() {
        Map<String, AttributeValue> attributes = new HashMap<>(attribs);
        attributes.put("newAttribute", new AttributeValue().withS("foo"));
        Parameters<? extends SignOnlyWithUnknownAttributeAnnotation> params = FakeParameters.getInstance(
                SignOnlyWithUnknownAttributeAnnotationWithNewAttribute.class, attributes, null,
                TABLE_NAME, HASH_KEY, RANGE_KEY);
        Map<String, AttributeValue> encryptedAttributes = encryptor.transform(params);
        assertThat(encryptedAttributes, AttrMatcher.invert(attributes));
        assertAttrEquals(new AttributeValue().withS("foo"), encryptedAttributes.get("newAttribute"));
        params = FakeParameters.getInstance(
                SignOnlyWithUnknownAttributeAnnotation.class, encryptedAttributes, null,
                TABLE_NAME, HASH_KEY, RANGE_KEY);
        encryptedAttributes.get("newAttribute").setS("bar");
        encryptor.untransform(params);
    }

    @Test
    public void testEncryptWithUnknownAttributeAnnotation() {
        Map<String, AttributeValue> attributes = new HashMap<>(attribs);
        attributes.put("newAttribute", new AttributeValue().withS("foo"));
        Parameters<? extends BaseClassWithUnknownAttributeAnnotation> params = FakeParameters.getInstance(
                BaseClassWithNewAttribute.class, attributes, null,
                TABLE_NAME, HASH_KEY, RANGE_KEY);
        Map<String, AttributeValue> encryptedAttributes = encryptor.transform(params);
        assertThat(encryptedAttributes, AttrMatcher.invert(attributes));
        params = FakeParameters.getInstance(
                BaseClassWithUnknownAttributeAnnotation.class, encryptedAttributes, null,
                TABLE_NAME, HASH_KEY, RANGE_KEY);
        Map<String, AttributeValue> decryptedAttributes = encryptor.untransform(params);
        assertThat(decryptedAttributes, AttrMatcher.match(attributes));
    }

    @Test(expectedExceptions = DynamoDBMappingException.class)
    public void testEncryptWithUnknownAttributeAnnotationBadSignature() {
        Map<String, AttributeValue> attributes = new HashMap<>(attribs);
        attributes.put("newAttribute", new AttributeValue().withS("foo"));
        Parameters<? extends BaseClassWithUnknownAttributeAnnotation> params = FakeParameters.getInstance(
                BaseClassWithNewAttribute.class, attributes, null,
                TABLE_NAME, HASH_KEY, RANGE_KEY);
        Map<String, AttributeValue> encryptedAttributes = encryptor.transform(params);
        assertThat(encryptedAttributes, AttrMatcher.invert(attributes));
        params = FakeParameters.getInstance(
                BaseClassWithUnknownAttributeAnnotation.class, encryptedAttributes, null,
                TABLE_NAME, HASH_KEY, RANGE_KEY);
        encryptedAttributes.get("newAttribute").setB(ByteBuffer.allocate(0));
        encryptor.untransform(params);
    }

    @Test
    public void testEncryptWithFieldLevelDoNotEncryptAnnotation() {
        Map<String, AttributeValue> attributes = new HashMap<>(attribs);
        attributes.put("value", new AttributeValue().withN("100"));
        Parameters<? extends DoNotEncryptField> params = FakeParameters.getInstance(
            DoNotEncryptField.class, attributes, null,
            TABLE_NAME, HASH_KEY, RANGE_KEY);
        Map<String, AttributeValue> encryptedAttributes = encryptor.transform(params);
        assertThat(encryptedAttributes, AttrMatcher.invert(attributes));
        assertAttrEquals(attributes.get("value"), encryptedAttributes.get("value"));
        params = FakeParameters.getInstance(
            DoNotEncryptField.class, encryptedAttributes, null,
            TABLE_NAME, HASH_KEY, RANGE_KEY);
        Map<String, AttributeValue> decryptedAttributes = encryptor.untransform(params);
        assertThat(decryptedAttributes, AttrMatcher.match(attributes));
    }

    @Test
    public void testEncryptWithFieldLevelDoNotEncryptAnnotationWithChangedDoNotTouchSuperClass() {
        Map<String, AttributeValue> attributes = new HashMap<>(attribs);
        attributes.put("value", new AttributeValue().withN("100"));
        Parameters<? extends DoNotEncryptField> params = FakeParameters.getInstance(
            DoNotEncryptField.class, attributes, null,
            TABLE_NAME, HASH_KEY, RANGE_KEY);
        Map<String, AttributeValue> encryptedAttributes = encryptor.transform(params);
        assertThat(encryptedAttributes, AttrMatcher.invert(attributes));
        assertAttrEquals(attributes.get("value"), encryptedAttributes.get("value"));
        params = FakeParameters.getInstance(
            DoNotEncryptField.class, encryptedAttributes, null,
            TABLE_NAME, HASH_KEY, RANGE_KEY);

        // Change a DoNotTouch value on Mixed super class
        encryptedAttributes.put("intValue", new AttributeValue().withN("666"));
        Map<String, AttributeValue> decryptedAttributes = encryptor.untransform(params);

        Map<String, AttributeValue> modifiedAttributes = new HashMap<>(attributes);
        modifiedAttributes.put("intValue", new AttributeValue().withN("666"));

        assertThat(decryptedAttributes, AttrMatcher.match(modifiedAttributes));
    }

    @Test(expectedExceptions = DynamoDBMappingException.class)
    public void testEncryptWithFieldLevelDoNotEncryptAnnotationBadSignature() {
        Map<String, AttributeValue> attributes = new HashMap<>(attribs);
        attributes.put("value", new AttributeValue().withN("100"));
        Parameters<? extends DoNotEncryptField> params = FakeParameters.getInstance(
            DoNotEncryptField.class, attributes, null,
            TABLE_NAME, HASH_KEY, RANGE_KEY);
        Map<String, AttributeValue> encryptedAttributes = encryptor.transform(params);
        assertThat(encryptedAttributes, AttrMatcher.invert(attributes));
        assertAttrEquals(attributes.get("value"), encryptedAttributes.get("value"));
        params = FakeParameters.getInstance(
            DoNotEncryptField.class, encryptedAttributes, null,
            TABLE_NAME, HASH_KEY, RANGE_KEY);
        encryptedAttributes.put("value", new AttributeValue().withN("200"));
        encryptor.untransform(params);
    }

    @Test(expectedExceptions = DynamoDBMappingException.class)
    public void testEncryptWithFieldLevelDoNotEncryptAnnotationBadSignatureSuperClass() {
        Map<String, AttributeValue> attributes = new HashMap<>(attribs);
        attributes.put("value", new AttributeValue().withN("100"));
        Parameters<? extends DoNotEncryptField> params = FakeParameters.getInstance(
            DoNotEncryptField.class, attributes, null,
            TABLE_NAME, HASH_KEY, RANGE_KEY);
        Map<String, AttributeValue> encryptedAttributes = encryptor.transform(params);
        assertThat(encryptedAttributes, AttrMatcher.invert(attributes));
        assertAttrEquals(attributes.get("value"), encryptedAttributes.get("value"));
        params = FakeParameters.getInstance(
            DoNotEncryptField.class, encryptedAttributes, null,
            TABLE_NAME, HASH_KEY, RANGE_KEY);

        // Change DoNotEncrypt value on Mixed super class
        encryptedAttributes.put("doubleValue", new AttributeValue().withN("200"));
        encryptor.untransform(params);
    }

    @Test
    public void testEncryptWithFieldLevelDoNotTouchAnnotation() {
        Map<String, AttributeValue> attributes = new HashMap<>(attribs);
        attributes.put("value", new AttributeValue().withN("100"));
        Parameters<? extends DoNotTouchField> params = FakeParameters.getInstance(
            DoNotTouchField.class, attributes, null,
            TABLE_NAME, HASH_KEY, RANGE_KEY);
        Map<String, AttributeValue> encryptedAttributes = encryptor.transform(params);
        assertThat(encryptedAttributes, AttrMatcher.invert(attributes));
        assertAttrEquals(attributes.get("value"), encryptedAttributes.get("value"));
        params = FakeParameters.getInstance(
            DoNotTouchField.class, encryptedAttributes, null,
            TABLE_NAME, HASH_KEY, RANGE_KEY);
        Map<String, AttributeValue> decryptedAttributes = encryptor.untransform(params);
        assertThat(decryptedAttributes, AttrMatcher.match(attributes));
    }

    @Test
    public void testEncryptWithFieldLevelDoNotTouchAnnotationChangeValue() {
        Map<String, AttributeValue> attributes = new HashMap<>(attribs);
        attributes.put("value", new AttributeValue().withN("100"));
        Parameters<? extends DoNotTouchField> params = FakeParameters.getInstance(
            DoNotTouchField.class, attributes, null,
            TABLE_NAME, HASH_KEY, RANGE_KEY);
        Map<String, AttributeValue> encryptedAttributes = encryptor.transform(params);
        assertThat(encryptedAttributes, AttrMatcher.invert(attributes));
        assertAttrEquals(attributes.get("value"), encryptedAttributes.get("value"));
        params = FakeParameters.getInstance(
            DoNotTouchField.class, encryptedAttributes, null,
            TABLE_NAME, HASH_KEY, RANGE_KEY);
        encryptedAttributes.put("value", new AttributeValue().withN("200"));
        Map<String, AttributeValue> decryptedAttributes = encryptor.untransform(params);
        assertThat(decryptedAttributes, AttrMatcher.invert(attributes));
        assertAttrEquals(new AttributeValue().withN("200"), decryptedAttributes.get("value"));

      // Change a DoNotTouch value on Mixed super class
      encryptedAttributes.put("intValue", new AttributeValue().withN("666"));
      decryptedAttributes = encryptor.untransform(params);

      Map<String, AttributeValue> modifiedAttributes = new HashMap<>(attributes);
      modifiedAttributes.put("intValue", new AttributeValue().withN("666"));
      modifiedAttributes.put("value", new AttributeValue().withN("200"));

      assertThat(decryptedAttributes, AttrMatcher.match(modifiedAttributes));
    }

    @Test(expectedExceptions = DynamoDBMappingException.class)
    public void testEncryptWithFieldLevelDoNotTouchAnnotationBadSignatureSuperClass() {
      Map<String, AttributeValue> attributes = new HashMap<>(attribs);
      attributes.put("value", new AttributeValue().withN("100"));
      Parameters<? extends DoNotTouchField> params = FakeParameters.getInstance(
          DoNotTouchField.class, attributes, null,
          TABLE_NAME, HASH_KEY, RANGE_KEY);
      Map<String, AttributeValue> encryptedAttributes = encryptor.transform(params);
      assertThat(encryptedAttributes, AttrMatcher.invert(attributes));
      assertAttrEquals(attributes.get("value"), encryptedAttributes.get("value"));
      params = FakeParameters.getInstance(
          DoNotTouchField.class, encryptedAttributes, null,
          TABLE_NAME, HASH_KEY, RANGE_KEY);

      Map<String, AttributeValue> decryptedAttributes = encryptor.untransform(params);
      assertThat(decryptedAttributes, AttrMatcher.match(attributes));

      // Change DoNotEncrypt value on Mixed super class
      encryptedAttributes.put("doubleValue", new AttributeValue().withN("200"));
      encryptor.untransform(params);
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
}
