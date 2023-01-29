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

import static com.google.common.collect.Sets.newHashSet;
import static java.util.stream.Collectors.toMap;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.not;
import static org.junit.jupiter.api.Assertions.*;
import static software.amazon.awssdk.enhanced.dynamodb.encryption.utils.EncryptionContextOperators.overrideEncryptionContextTableName;

import java.lang.reflect.Method;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.SignatureException;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.internal.util.collections.Sets;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.enhanced.dynamodb.encryption.materials.DecryptionMaterials;
import software.amazon.awssdk.enhanced.dynamodb.encryption.materials.EncryptionMaterials;
import software.amazon.awssdk.enhanced.dynamodb.encryption.providers.EncryptionMaterialsProvider;
import software.amazon.awssdk.enhanced.dynamodb.encryption.providers.SymmetricStaticProvider;
import software.amazon.awssdk.enhanced.dynamodb.internal.Utils;
import software.amazon.awssdk.enhanced.dynamodb.testing.AttrMatcher;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;

public class DynamoDBEncryptorTest {
    private static SecretKey encryptionKey;
    private static SecretKey macKey;

    private InstrumentedEncryptionMaterialsProvider prov;
    private DynamoDBEncryptor encryptor;
    private Map<String, AttributeValue> attribs;

    private EncryptionContext context;
    private static final String OVERRIDDEN_TABLE_NAME = "TheBestTableName";

    @BeforeAll
    public static void setUpClass() throws Exception {
        KeyGenerator aesGen = KeyGenerator.getInstance("AES");
        aesGen.init(128, Utils.getRng());
        encryptionKey = aesGen.generateKey();

        KeyGenerator macGen = KeyGenerator.getInstance("HmacSHA256");
        macGen.init(256, Utils.getRng());
        macKey = macGen.generateKey();
    }

    @BeforeEach
    public void setUp() throws Exception {
        prov =
                new InstrumentedEncryptionMaterialsProvider(
                        new SymmetricStaticProvider(
                                encryptionKey, macKey, Collections.<String, String>emptyMap()));
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

        // New(er) data types
        attribs.put("booleanTrue", AttributeValue.builder().bool(true).build());
        attribs.put("booleanFalse", AttributeValue.builder().bool(false).build());
        attribs.put("nullValue", AttributeValue.builder().nul(true).build());
        Map<String, AttributeValue> tmpMap = new HashMap<>(attribs);
        attribs.put(
                "listValue",
                AttributeValue.builder()
                        .l(
                                AttributeValue.builder().s("I'm a string").build(),
                                AttributeValue.builder().n("42").build(),
                                AttributeValue.builder().s("Another string").build(),
                                AttributeValue.builder().ns("1", "4", "7").build(),
                                AttributeValue.builder().m(tmpMap).build(),
                                AttributeValue.builder()
                                        .l(
                                                AttributeValue.builder().n("123").build(),
                                                AttributeValue.builder().ns("1", "200", "10", "15", "0").build(),
                                                AttributeValue.builder().ss("Goodbye", "Cruel", "World", "!").build())
                                        .build())
                        .build());
        tmpMap = new HashMap<>();
        tmpMap.put("another string", AttributeValue.builder().s("All around the cobbler's bench").build());
        tmpMap.put("next line", AttributeValue.builder().ss("the monkey", "chased", "the weasel").build());
        tmpMap.put(
                "more lyrics",
                AttributeValue.builder()
                        .l(
                                AttributeValue.builder().s("the monkey").build(),
                                AttributeValue.builder().s("thought twas").build(),
                                AttributeValue.builder().s("all in fun").build())
                        .build());
        tmpMap.put(
                "weasel",
                AttributeValue.builder()
                        .m(Collections.singletonMap("pop", AttributeValue.builder().bool(true).build())).build());
        attribs.put("song", AttributeValue.builder().m(tmpMap).build());

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

        // Make sure we're calling the proper getEncryptionMaterials method
        assertEquals(
                1,
                prov.getCallCount("getEncryptionMaterials(EncryptionContext context)"),
                "Wrong getEncryptionMaterials() called");
    }

    @Test
    public void ensureEncryptedAttributesUnmodified() throws GeneralSecurityException {
        Map<String, AttributeValue> encryptedAttributes =
                encryptor.encryptAllFieldsExcept(
                        Collections.unmodifiableMap(attribs), context, "hashKey", "rangeKey", "version");
        // Using TreeMap before casting to string to avoid nondeterministic key orders.
        String encryptedString = new TreeMap<>(encryptedAttributes).toString();
        encryptor.decryptAllFieldsExcept(
                Collections.unmodifiableMap(encryptedAttributes),
                context,
                "hashKey",
                "rangeKey",
                "version");

        assertEquals(encryptedString, new TreeMap<>(encryptedAttributes).toString());
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

        byte[] rawArray = encryptedAttributes.get(encryptor.getMaterialDescriptionFieldName()).b().asByteArray();
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
        prov =
                new InstrumentedEncryptionMaterialsProvider(
                        new SymmetricStaticProvider(null, macKey, Collections.<String, String>emptyMap()));
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

    /**
     * Tests that no exception is thrown when the encryption context override operator is null
     *
     * @throws GeneralSecurityException
     */
    @Test
    public void testNullEncryptionContextOperator() throws GeneralSecurityException {
        DynamoDBEncryptor encryptor = DynamoDBEncryptor.getInstance(prov);
        encryptor.setEncryptionContextOverrideOperator(null);
        encryptor.encryptAllFieldsExcept(attribs, context, Collections.emptyList());
    }

    /**
     * Tests decrypt and encrypt with an encryption context override operator
     *
     * @throws GeneralSecurityException
     */
    @Test
    public void testTableNameOverriddenEncryptionContextOperator() throws GeneralSecurityException {
        // Ensure that the table name is different from what we override the table to.
        assertThat(context.getTableName(), not(equalTo(OVERRIDDEN_TABLE_NAME)));
        DynamoDBEncryptor encryptor = DynamoDBEncryptor.getInstance(prov);
        encryptor.setEncryptionContextOverrideOperator(
                overrideEncryptionContextTableName(context.getTableName(), OVERRIDDEN_TABLE_NAME));
        Map<String, AttributeValue> encryptedItems =
                encryptor.encryptAllFieldsExcept(attribs, context, Collections.emptyList());
        Map<String, AttributeValue> decryptedItems =
                encryptor.decryptAllFieldsExcept(encryptedItems, context, Collections.emptyList());
        assertThat(decryptedItems, AttrMatcher.match(attribs));
    }

    /**
     * Tests encrypt with an encryption context override operator, and a second encryptor without an
     * override
     *
     * @throws GeneralSecurityException
     */
    @Test
    public void testTableNameOverriddenEncryptionContextOperatorWithSecondEncryptor()
            throws GeneralSecurityException {
        // Ensure that the table name is different from what we override the table to.
        assertThat(context.getTableName(), not(equalTo(OVERRIDDEN_TABLE_NAME)));
        DynamoDBEncryptor encryptor = DynamoDBEncryptor.getInstance(prov);
        DynamoDBEncryptor encryptorWithoutOverride = DynamoDBEncryptor.getInstance(prov);
        encryptor.setEncryptionContextOverrideOperator(
                overrideEncryptionContextTableName(context.getTableName(), OVERRIDDEN_TABLE_NAME));
        Map<String, AttributeValue> encryptedItems =
                encryptor.encryptAllFieldsExcept(attribs, context, Collections.emptyList());

        EncryptionContext expectedOverriddenContext =
                new EncryptionContext.Builder(context).withTableName("TheBestTableName").build();
        Map<String, AttributeValue> decryptedItems =
                encryptorWithoutOverride.decryptAllFieldsExcept(
                        encryptedItems, expectedOverriddenContext, Collections.emptyList());
        assertThat(decryptedItems, AttrMatcher.match(attribs));
    }

    /**
     * Tests encrypt with an encryption context override operator, and a second encryptor without an
     * override
     *
     * @throws GeneralSecurityException
     */
    @Test
    public void
    testTableNameOverriddenEncryptionContextOperatorWithSecondEncryptorButTheOriginalEncryptionContext()
            throws GeneralSecurityException {
        // Ensure that the table name is different from what we override the table to.
        assertThat(context.getTableName(), not(equalTo(OVERRIDDEN_TABLE_NAME)));
        DynamoDBEncryptor encryptor = DynamoDBEncryptor.getInstance(prov);
        DynamoDBEncryptor encryptorWithoutOverride = DynamoDBEncryptor.getInstance(prov);
        encryptor.setEncryptionContextOverrideOperator(
                overrideEncryptionContextTableName(context.getTableName(), OVERRIDDEN_TABLE_NAME));
        Map<String, AttributeValue> encryptedItems =
                encryptor.encryptAllFieldsExcept(attribs, context, Collections.emptyList());

        // Use the original encryption context, and expect a signature failure
        assertThrows(SignatureException.class, () ->
                encryptorWithoutOverride.decryptAllFieldsExcept(
                        encryptedItems, context, Collections.emptyList()));
    }

    @Test
    public void EcdsaSignedOnly() throws GeneralSecurityException {

        encryptor = DynamoDBEncryptor.getInstance(getMaterialProviderwithECDSA());

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
    public void EcdsaSignedOnlyBadSignature() throws GeneralSecurityException {

        encryptor = DynamoDBEncryptor.getInstance(getMaterialProviderwithECDSA());

        Map<String, AttributeValue> encryptedAttributes =
                encryptor.encryptAllFieldsExcept(attribs, context, attribs.keySet().toArray(new String[0]));
        assertThat(encryptedAttributes, AttrMatcher.invert(attribs));
        encryptedAttributes.put("hashKey", AttributeValue.builder().n("666").build());
        assertThrows(SignatureException.class, () ->
        encryptor.decryptAllFieldsExcept(
                encryptedAttributes, context, attribs.keySet().toArray(new String[0])));
    }

    @Test
    public void toByteArray() throws ReflectiveOperationException {
        final byte[] expected = new byte[]{0, 1, 2, 3, 4, 5};
        assertToByteArray("Wrap", expected, ByteBuffer.wrap(expected));
        assertToByteArray("Wrap-RO", expected, ByteBuffer.wrap(expected).asReadOnlyBuffer());

        assertToByteArray(
                "Wrap-Truncated-Sliced",
                expected,
                ByteBuffer.wrap(new byte[]{0, 1, 2, 3, 4, 5, 6}, 0, 6).slice());
        assertToByteArray(
                "Wrap-Offset-Sliced",
                expected,
                ByteBuffer.wrap(new byte[]{6, 0, 1, 2, 3, 4, 5, 6}, 1, 6).slice());
        assertToByteArray(
                "Wrap-Truncated", expected, ByteBuffer.wrap(new byte[]{0, 1, 2, 3, 4, 5, 6}, 0, 6));
        assertToByteArray(
                "Wrap-Offset", expected, ByteBuffer.wrap(new byte[]{6, 0, 1, 2, 3, 4, 5, 6}, 1, 6));

        ByteBuffer buff = ByteBuffer.allocate(expected.length + 10);
        buff.put(expected);
        buff.flip();
        assertToByteArray("Normal", expected, buff);

        buff = ByteBuffer.allocateDirect(expected.length + 10);
        buff.put(expected);
        buff.flip();
        assertToByteArray("Direct", expected, buff);
    }

    @Test
    public void testDecryptWithPlaintextItem() throws GeneralSecurityException {
        Map<String, Set<EncryptionFlags>> attributeWithEmptyEncryptionFlags =
                attribs.keySet().stream().collect(toMap(k -> k, k -> newHashSet()));

        Map<String, AttributeValue> decryptedAttributes =
                encryptor.decryptRecord(attribs, attributeWithEmptyEncryptionFlags, context);
        assertThat(decryptedAttributes, AttrMatcher.match(attribs));
    }

    /*
    Test decrypt with a map that contains a new key (not included in attribs) with an encryption flag set that contains ENCRYPT and SIGN.
     */
    @Test
    public void testDecryptWithPlainTextItemAndAdditionNewAttributeHavingEncryptionFlag()
            throws GeneralSecurityException {
        Map<String, Set<EncryptionFlags>> attributeWithEmptyEncryptionFlags =
                attribs.keySet().stream().collect(toMap(k -> k, k -> newHashSet()));
        attributeWithEmptyEncryptionFlags.put(
                "newAttribute", Sets.newSet(EncryptionFlags.ENCRYPT, EncryptionFlags.SIGN));

        Map<String, AttributeValue> decryptedAttributes =
                encryptor.decryptRecord(attribs, attributeWithEmptyEncryptionFlags, context);
        assertThat(decryptedAttributes, AttrMatcher.match(attribs));
    }

    private void assertToByteArray(
            final String msg, final byte[] expected, final ByteBuffer testValue)
            throws ReflectiveOperationException {
        Method m = DynamoDBEncryptor.class.getDeclaredMethod("toByteArray", ByteBuffer.class);
        m.setAccessible(true);

        int oldPosition = testValue.position();
        int oldLimit = testValue.limit();

        assertArrayEquals(expected, (byte[]) m.invoke(null, testValue), msg + ":Array");
        assertEquals(oldPosition, testValue.position(), msg + ":Position");
        assertEquals(oldLimit, testValue.limit(), msg + ":Limit");
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

    private static final class InstrumentedEncryptionMaterialsProvider
            implements EncryptionMaterialsProvider {
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
