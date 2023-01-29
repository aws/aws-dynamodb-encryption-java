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
package software.amazon.awssdk.enhanced.dynamodb.encryption;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.*;

import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SignatureException;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.enhanced.dynamodb.encryption.providers.EncryptionMaterialsProvider;
import software.amazon.awssdk.enhanced.dynamodb.encryption.providers.SymmetricStaticProvider;
import software.amazon.awssdk.enhanced.dynamodb.encryption.providers.WrappedMaterialsProvider;
import software.amazon.awssdk.enhanced.dynamodb.internal.Utils;
import software.amazon.awssdk.enhanced.dynamodb.testing.AttrMatcher;
import software.amazon.awssdk.enhanced.dynamodb.testing.TestDelegatedKey;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;

public class DelegatedEnvelopeEncryptionTest {
    private static SecretKeySpec rawEncryptionKey;
    private static SecretKeySpec rawMacKey;
    private static DelegatedKey encryptionKey;
    private static DelegatedKey macKey;

    private EncryptionMaterialsProvider prov;
    private DynamoDBEncryptor encryptor;
    private Map<String, AttributeValue> attribs;
    private EncryptionContext context;

    @BeforeAll
    public static void setupClass() throws Exception {
        rawEncryptionKey = new SecretKeySpec(Utils.getRandom(32), "AES");
        encryptionKey = new TestDelegatedKey(rawEncryptionKey);

        rawMacKey = new SecretKeySpec(Utils.getRandom(32), "HmacSHA256");
        macKey = new TestDelegatedKey(rawMacKey);
    }

    @BeforeEach
    public void setUp() throws Exception {
        prov =
                new WrappedMaterialsProvider(
                        encryptionKey, encryptionKey, macKey, Collections.<String, String>emptyMap());
        encryptor = DynamoDBEncryptor.getInstance(prov, "encryptor-");

        attribs = new HashMap<String, AttributeValue>();
        attribs.put("intValue", AttributeValue.builder().n("123").build());
        attribs.put("stringValue", AttributeValue.builder().s("Hello world!").build());
        attribs.put(
                "byteArrayValue",
                AttributeValue.builder().b(SdkBytes.fromByteArray(new byte[]{0, 1, 2, 3, 4, 5})).build());
        attribs.put("stringSet", AttributeValue.builder().ss("Goodbye", "Cruel", "World", "?").build());
        attribs.put("intSet", AttributeValue.builder().ns("1", "200", "10", "15", "0").build());
        attribs.put("hashKey", AttributeValue.builder().n("5").build());
        attribs.put("rangeKey", AttributeValue.builder().n("7").build());
        attribs.put("version", AttributeValue.builder().n("0").build());

        context =
                new EncryptionContext.Builder()
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
                encryptor.encryptAllFieldsExcept(
                        Collections.unmodifiableMap(attribs), context, "hashKey", "rangeKey", "version");
        assertThat(encryptedAttributes, AttrMatcher.invert(attribs));
        Map<String, AttributeValue> decryptedAttributes =
                encryptor.decryptAllFieldsExcept(
                        Collections.unmodifiableMap(encryptedAttributes),
                        context,
                        "hashKey",
                        "rangeKey",
                        "version");
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

    @Test
    public void fullEncryptionBadSignature() throws GeneralSecurityException {
        Map<String, AttributeValue> encryptedAttributes =
                encryptor.encryptAllFieldsExcept(
                        Collections.unmodifiableMap(attribs), context, "hashKey", "rangeKey", "version");
        assertThat(encryptedAttributes, AttrMatcher.invert(attribs));
        encryptedAttributes.put("hashKey", AttributeValue.builder().n("666").build());

        assertThrows(SignatureException.class, () ->
                encryptor.decryptAllFieldsExcept(
                        Collections.unmodifiableMap(encryptedAttributes),
                        context,
                        "hashKey",
                        "rangeKey",
                        "version"));
    }

    @Test
    public void badVersionNumber() throws GeneralSecurityException {
        Map<String, AttributeValue> encryptedAttributes =
                encryptor.encryptAllFieldsExcept(
                        Collections.unmodifiableMap(attribs), context, "hashKey", "rangeKey", "version");
        byte[] rawArray =
                encryptedAttributes.get(encryptor.getMaterialDescriptionFieldName()).b().asByteArray();
        assertEquals(0, rawArray[0]); // This will need to be kept in sync with the current version.
        rawArray[0] = 100;
        encryptedAttributes.put(
                encryptor.getMaterialDescriptionFieldName(),
                AttributeValue.builder().b(SdkBytes.fromByteArray(rawArray)).build());

        assertThrows(IllegalArgumentException.class, () ->
                encryptor.decryptAllFieldsExcept(
                        Collections.unmodifiableMap(encryptedAttributes),
                        context,
                        "hashKey",
                        "rangeKey",
                        "version"));
    }

    @Test
    public void signedOnly() throws GeneralSecurityException {
        Map<String, AttributeValue> encryptedAttributes =
                encryptor.encryptAllFieldsExcept(attribs, context, attribs.keySet().toArray(new String[0]));
        assertThat(encryptedAttributes, AttrMatcher.invert(attribs));
        Map<String, AttributeValue> decryptedAttributes =
                encryptor.decryptAllFieldsExcept(
                        encryptedAttributes, context, attribs.keySet().toArray(new String[0]));
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
        prov = new SymmetricStaticProvider(null, macKey, Collections.<String, String>emptyMap());
        encryptor = DynamoDBEncryptor.getInstance(prov, "encryptor-");
        Map<String, AttributeValue> encryptedAttributes =
                encryptor.encryptAllFieldsExcept(attribs, context, attribs.keySet().toArray(new String[0]));
        assertThat(encryptedAttributes, AttrMatcher.invert(attribs));
        Map<String, AttributeValue> decryptedAttributes =
                encryptor.decryptAllFieldsExcept(
                        encryptedAttributes, context, attribs.keySet().toArray(new String[0]));
        assertThat(decryptedAttributes, AttrMatcher.match(attribs));

        // Make sure keys and version are not encrypted
        assertAttrEquals(attribs.get("hashKey"), encryptedAttributes.get("hashKey"));
        assertAttrEquals(attribs.get("rangeKey"), encryptedAttributes.get("rangeKey"));
        assertAttrEquals(attribs.get("version"), encryptedAttributes.get("version"));

        // Make sure String has not been encrypted (we'll assume the others are correct as well)
        assertAttrEquals(attribs.get("stringValue"), encryptedAttributes.get("stringValue"));
    }

    @Test
    public void signedOnlyBadSignature() throws GeneralSecurityException {
        Map<String, AttributeValue> encryptedAttributes =
                encryptor.encryptAllFieldsExcept(attribs, context, attribs.keySet().toArray(new String[0]));
        assertThat(encryptedAttributes, AttrMatcher.invert(attribs));
        encryptedAttributes.put("hashKey", AttributeValue.builder().n("666").build());

        assertThrows(SignatureException.class, () ->
                encryptor.decryptAllFieldsExcept(
                        encryptedAttributes, context, attribs.keySet().toArray(new String[0])));
    }

    @Test
    public void signedOnlyNoSignature() throws GeneralSecurityException {
        Map<String, AttributeValue> encryptedAttributes =
                encryptor.encryptAllFieldsExcept(attribs, context, attribs.keySet().toArray(new String[0]));
        assertThat(encryptedAttributes, AttrMatcher.invert(attribs));
        encryptedAttributes.remove(encryptor.getSignatureFieldName());


        assertThrows(SignatureException.class, () ->
                encryptor.decryptAllFieldsExcept(
                        encryptedAttributes, context, attribs.keySet().toArray(new String[0])));
    }

    @Test
    public void RsaSignedOnly() throws GeneralSecurityException {
        KeyPairGenerator rsaGen = KeyPairGenerator.getInstance("RSA");
        rsaGen.initialize(2048, Utils.getRng());
        KeyPair sigPair = rsaGen.generateKeyPair();
        encryptor =
                DynamoDBEncryptor.getInstance(
                        new SymmetricStaticProvider(
                                encryptionKey, sigPair, Collections.<String, String>emptyMap()),
                        "encryptor-");

        Map<String, AttributeValue> encryptedAttributes =
                encryptor.encryptAllFieldsExcept(attribs, context, attribs.keySet().toArray(new String[0]));
        assertThat(encryptedAttributes, AttrMatcher.invert(attribs));
        Map<String, AttributeValue> decryptedAttributes =
                encryptor.decryptAllFieldsExcept(
                        encryptedAttributes, context, attribs.keySet().toArray(new String[0]));
        assertThat(decryptedAttributes, AttrMatcher.match(attribs));

        // Make sure keys and version are not encrypted
        assertAttrEquals(attribs.get("hashKey"), encryptedAttributes.get("hashKey"));
        assertAttrEquals(attribs.get("rangeKey"), encryptedAttributes.get("rangeKey"));
        assertAttrEquals(attribs.get("version"), encryptedAttributes.get("version"));

        // Make sure String has not been encrypted (we'll assume the others are correct as well)
        assertAttrEquals(attribs.get("stringValue"), encryptedAttributes.get("stringValue"));
    }

    @Test
    public void RsaSignedOnlyBadSignature() throws GeneralSecurityException {
        KeyPairGenerator rsaGen = KeyPairGenerator.getInstance("RSA");
        rsaGen.initialize(2048, Utils.getRng());
        KeyPair sigPair = rsaGen.generateKeyPair();
        encryptor =
                DynamoDBEncryptor.getInstance(
                        new SymmetricStaticProvider(
                                encryptionKey, sigPair, Collections.<String, String>emptyMap()),
                        "encryptor-");

        Map<String, AttributeValue> encryptedAttributes =
                encryptor.encryptAllFieldsExcept(attribs, context, attribs.keySet().toArray(new String[0]));
        assertThat(encryptedAttributes, AttrMatcher.invert(attribs));
        encryptedAttributes.put("hashKey", AttributeValue.builder().n("666").build());

        assertThrows(SignatureException.class, () ->
        encryptor.decryptAllFieldsExcept(
                encryptedAttributes, context, attribs.keySet().toArray(new String[0])));
    }

    private void assertAttrEquals(AttributeValue o1, AttributeValue o2) {
        Assertions.assertEquals(o1.b(), o2.b());
        assertSetsEqual(o1.bs(), o2.bs());
        Assertions.assertEquals(o1.n(), o2.n());
        assertSetsEqual(o1.ns(), o2.ns());
        Assertions.assertEquals(o1.s(), o2.s());
        assertSetsEqual(o1.ss(), o2.ss());
    }

    private <T> void assertSetsEqual(Collection<T> c1, Collection<T> c2) {
        Assertions.assertFalse(c1 == null ^ c2 == null);
        if (c1 != null) {
            Set<T> s1 = new HashSet<T>(c1);
            Set<T> s2 = new HashSet<T>(c2);
            Assertions.assertEquals(s1, s2);
        }
    }
}
