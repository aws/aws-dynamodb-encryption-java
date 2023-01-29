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

import static org.junit.jupiter.api.Assertions.*;

import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.SignatureException;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import javax.crypto.KeyGenerator;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.enhanced.dynamodb.internal.Utils;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;


public class DynamoDBSignerTest {
    // These use the Key type (rather than PublicKey, PrivateKey, and SecretKey)
    // to test the routing logic within the signer.
    private static Key pubKeyRsa;
    private static Key privKeyRsa;
    private static Key macKey;
    private DynamoDBSigner signerRsa;
    private DynamoDBSigner signerEcdsa;
    private static Key pubKeyEcdsa;
    private static Key privKeyEcdsa;

    @BeforeAll
    public static void setUpClass() throws Exception {

        // RSA key generation
        KeyPairGenerator rsaGen = KeyPairGenerator.getInstance("RSA");
        rsaGen.initialize(2048, Utils.getRng());
        KeyPair sigPair = rsaGen.generateKeyPair();
        pubKeyRsa = sigPair.getPublic();
        privKeyRsa = sigPair.getPrivate();

        KeyGenerator macGen = KeyGenerator.getInstance("HmacSHA256");
        macGen.init(256, Utils.getRng());
        macKey = macGen.generateKey();

        Security.addProvider(new BouncyCastleProvider());
        ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("secp384r1");
        KeyPairGenerator g = KeyPairGenerator.getInstance("ECDSA", "BC");
        g.initialize(ecSpec, Utils.getRng());
        KeyPair keypair = g.generateKeyPair();
        pubKeyEcdsa = keypair.getPublic();
        privKeyEcdsa = keypair.getPrivate();
    }

    @BeforeEach
    public void setUp() {
        signerRsa = DynamoDBSigner.getInstance("SHA256withRSA", Utils.getRng());
        signerEcdsa = DynamoDBSigner.getInstance("SHA384withECDSA", Utils.getRng());
    }

    @Test
    public void mac() throws GeneralSecurityException {
        Map<String, AttributeValue> itemAttributes = new HashMap<String, AttributeValue>();
        Map<String, Set<EncryptionFlags>> attributeFlags = new HashMap<String, Set<EncryptionFlags>>();

        itemAttributes.put("Key1", AttributeValue.builder().s("Value1").build());
        attributeFlags.put("Key1", EnumSet.of(EncryptionFlags.SIGN));
        itemAttributes.put("Key2", AttributeValue.builder().n("100").build());
        attributeFlags.put("Key2", EnumSet.of(EncryptionFlags.SIGN));
        itemAttributes.put(
                "Key3", AttributeValue.builder().b(SdkBytes.fromByteArray(new byte[]{0, 1, 2, 3})).build());
        attributeFlags.put("Key3", EnumSet.of(EncryptionFlags.SIGN, EncryptionFlags.ENCRYPT));
        byte[] signature =
                signerRsa.calculateSignature(itemAttributes, attributeFlags, new byte[0], macKey);

        signerRsa.verifySignature(
                itemAttributes, attributeFlags, new byte[0], macKey, ByteBuffer.wrap(signature));
    }

    @Test
    public void macLists() throws GeneralSecurityException {
        Map<String, AttributeValue> itemAttributes = new HashMap<String, AttributeValue>();
        Map<String, Set<EncryptionFlags>> attributeFlags = new HashMap<String, Set<EncryptionFlags>>();

        itemAttributes.put("Key1", AttributeValue.builder().ss("Value1", "Value2", "Value3").build());
        attributeFlags.put("Key1", EnumSet.of(EncryptionFlags.SIGN));
        itemAttributes.put("Key2", AttributeValue.builder().ns("100", "200", "300").build());
        attributeFlags.put("Key2", EnumSet.of(EncryptionFlags.SIGN));
        itemAttributes.put(
                "Key3",
                AttributeValue.builder()
                        .bs(
                                SdkBytes.fromByteArray(new byte[]{0, 1, 2, 3}), SdkBytes.fromByteArray(new byte[]{3, 2, 1})).build());
        attributeFlags.put("Key3", EnumSet.of(EncryptionFlags.SIGN, EncryptionFlags.ENCRYPT));
        byte[] signature =
                signerRsa.calculateSignature(itemAttributes, attributeFlags, new byte[0], macKey);

        signerRsa.verifySignature(
                itemAttributes, attributeFlags, new byte[0], macKey, ByteBuffer.wrap(signature));
    }

    @Test
    public void macListsUnsorted() throws GeneralSecurityException {
        Map<String, AttributeValue> itemAttributes = new HashMap<String, AttributeValue>();
        Map<String, Set<EncryptionFlags>> attributeFlags = new HashMap<String, Set<EncryptionFlags>>();

        itemAttributes.put("Key1", AttributeValue.builder().ss("Value3", "Value1", "Value2").build());
        attributeFlags.put("Key1", EnumSet.of(EncryptionFlags.SIGN));
        itemAttributes.put("Key2", AttributeValue.builder().ns("100", "300", "200").build());
        attributeFlags.put("Key2", EnumSet.of(EncryptionFlags.SIGN));
        itemAttributes.put(
                "Key3",
                AttributeValue.builder()
                        .bs(
                                SdkBytes.fromByteArray(new byte[]{3, 2, 1}),
                                SdkBytes.fromByteArray(new byte[]{0, 1, 2, 3}))
                        .build());
        attributeFlags.put("Key3", EnumSet.of(EncryptionFlags.SIGN, EncryptionFlags.ENCRYPT));
        byte[] signature =
                signerRsa.calculateSignature(itemAttributes, attributeFlags, new byte[0], macKey);

        Map<String, AttributeValue> scrambledAttributes = new HashMap<String, AttributeValue>();
        scrambledAttributes.put("Key1", AttributeValue.builder().ss("Value1", "Value2", "Value3").build());
        scrambledAttributes.put("Key2", AttributeValue.builder().ns("100", "200", "300").build());
        scrambledAttributes.put(
                "Key3",
                AttributeValue.builder()
                        .bs(
                                SdkBytes.fromByteArray(new byte[]{0, 1, 2, 3}),
                                SdkBytes.fromByteArray(new byte[]{3, 2, 1}))
                       .build());

        signerRsa.verifySignature(
                scrambledAttributes, attributeFlags, new byte[0], macKey, ByteBuffer.wrap(signature));
    }

    @Test
    public void macNoAdMatchesEmptyAd() throws GeneralSecurityException {
        Map<String, AttributeValue> itemAttributes = new HashMap<String, AttributeValue>();
        Map<String, Set<EncryptionFlags>> attributeFlags = new HashMap<String, Set<EncryptionFlags>>();

        itemAttributes.put("Key1", AttributeValue.builder().s("Value1").build());
        attributeFlags.put("Key1", EnumSet.of(EncryptionFlags.SIGN));
        itemAttributes.put("Key2", AttributeValue.builder().n("100").build());
        attributeFlags.put("Key2", EnumSet.of(EncryptionFlags.SIGN));
        itemAttributes.put(
                "Key3", AttributeValue.builder().b(SdkBytes.fromByteArray(new byte[]{0, 1, 2, 3})).build());
        attributeFlags.put("Key3", EnumSet.of(EncryptionFlags.SIGN, EncryptionFlags.ENCRYPT));
        byte[] signature = signerRsa.calculateSignature(itemAttributes, attributeFlags, null, macKey);

        signerRsa.verifySignature(
                itemAttributes, attributeFlags, new byte[0], macKey, ByteBuffer.wrap(signature));
    }

    @Test
    public void macWithIgnoredChange() throws GeneralSecurityException {
        Map<String, AttributeValue> itemAttributes = new HashMap<String, AttributeValue>();
        Map<String, Set<EncryptionFlags>> attributeFlags = new HashMap<String, Set<EncryptionFlags>>();

        itemAttributes.put("Key1", AttributeValue.builder().s("Value1").build());
        attributeFlags.put("Key1", EnumSet.of(EncryptionFlags.SIGN));
        itemAttributes.put("Key2", AttributeValue.builder().n("100").build());
        attributeFlags.put("Key2", EnumSet.of(EncryptionFlags.SIGN));
        itemAttributes.put(
                "Key3", AttributeValue.builder().b(SdkBytes.fromByteArray(new byte[]{0, 1, 2, 3})).build());
        attributeFlags.put("Key3", EnumSet.of(EncryptionFlags.SIGN, EncryptionFlags.ENCRYPT));
        itemAttributes.put("Key4", AttributeValue.builder().s("Ignored Value").build());
        byte[] signature =
                signerRsa.calculateSignature(itemAttributes, attributeFlags, new byte[0], macKey);

        itemAttributes.put("Key4", AttributeValue.builder().s("New Ignored Value").build());
        signerRsa.verifySignature(
                itemAttributes, attributeFlags, new byte[0], macKey, ByteBuffer.wrap(signature));
    }

    @Test
    public void macChangedValue() throws GeneralSecurityException {
        Map<String, AttributeValue> itemAttributes = new HashMap<String, AttributeValue>();
        Map<String, Set<EncryptionFlags>> attributeFlags = new HashMap<String, Set<EncryptionFlags>>();

        itemAttributes.put("Key1", AttributeValue.builder().s("Value1").build());
        attributeFlags.put("Key1", EnumSet.of(EncryptionFlags.SIGN));
        itemAttributes.put("Key2", AttributeValue.builder().n("100").build());
        attributeFlags.put("Key2", EnumSet.of(EncryptionFlags.SIGN));
        itemAttributes.put(
                "Key3", AttributeValue.builder().b(SdkBytes.fromByteArray(new byte[]{0, 1, 2, 3})).build());
        attributeFlags.put("Key3", EnumSet.of(EncryptionFlags.SIGN, EncryptionFlags.ENCRYPT));
        byte[] signature =
                signerRsa.calculateSignature(itemAttributes, attributeFlags, new byte[0], macKey);

        itemAttributes.put("Key2", AttributeValue.builder().n("99").build());

        assertThrows(SignatureException.class, () ->
        signerRsa.verifySignature(
                itemAttributes, attributeFlags, new byte[0], macKey, ByteBuffer.wrap(signature)));
    }

    @Test
    public void macChangedFlag() throws GeneralSecurityException {
        Map<String, AttributeValue> itemAttributes = new HashMap<String, AttributeValue>();
        Map<String, Set<EncryptionFlags>> attributeFlags = new HashMap<String, Set<EncryptionFlags>>();

        itemAttributes.put("Key1", AttributeValue.builder().s("Value1").build());
        attributeFlags.put("Key1", EnumSet.of(EncryptionFlags.SIGN));
        itemAttributes.put("Key2", AttributeValue.builder().n("100").build());
        attributeFlags.put("Key2", EnumSet.of(EncryptionFlags.SIGN));
        itemAttributes.put(
                "Key3", AttributeValue.builder().b(SdkBytes.fromByteArray(new byte[]{0, 1, 2, 3})).build());
        attributeFlags.put("Key3", EnumSet.of(EncryptionFlags.SIGN, EncryptionFlags.ENCRYPT));
        byte[] signature =
                signerRsa.calculateSignature(itemAttributes, attributeFlags, new byte[0], macKey);

        attributeFlags.put("Key3", EnumSet.of(EncryptionFlags.SIGN));

        assertThrows(SignatureException.class, () ->
        signerRsa.verifySignature(
                itemAttributes, attributeFlags, new byte[0], macKey, ByteBuffer.wrap(signature)));
    }

    @Test
    public void macChangedAssociatedData() throws GeneralSecurityException {
        Map<String, AttributeValue> itemAttributes = new HashMap<String, AttributeValue>();
        Map<String, Set<EncryptionFlags>> attributeFlags = new HashMap<String, Set<EncryptionFlags>>();

        itemAttributes.put("Key1", AttributeValue.builder().s("Value1").build());
        attributeFlags.put("Key1", EnumSet.of(EncryptionFlags.SIGN));
        itemAttributes.put("Key2", AttributeValue.builder().n("100").build());
        attributeFlags.put("Key2", EnumSet.of(EncryptionFlags.SIGN));
        itemAttributes.put(
                "Key3", AttributeValue.builder().b(SdkBytes.fromByteArray(new byte[]{0, 1, 2, 3})).build());
        attributeFlags.put("Key3", EnumSet.of(EncryptionFlags.SIGN, EncryptionFlags.ENCRYPT));
        byte[] signature =
                signerRsa.calculateSignature(itemAttributes, attributeFlags, new byte[]{3, 2, 1}, macKey);

        assertThrows(SignatureException.class, () ->
        signerRsa.verifySignature(
                itemAttributes, attributeFlags, new byte[]{1, 2, 3}, macKey, ByteBuffer.wrap(signature)));
    }

    @Test
    public void sig() throws GeneralSecurityException {
        Map<String, AttributeValue> itemAttributes = new HashMap<String, AttributeValue>();
        Map<String, Set<EncryptionFlags>> attributeFlags = new HashMap<String, Set<EncryptionFlags>>();

        itemAttributes.put("Key1", AttributeValue.builder().s("Value1").build());
        attributeFlags.put("Key1", EnumSet.of(EncryptionFlags.SIGN));
        itemAttributes.put("Key2", AttributeValue.builder().n("100").build());
        attributeFlags.put("Key2", EnumSet.of(EncryptionFlags.SIGN));
        itemAttributes.put(
                "Key3", AttributeValue.builder().b(SdkBytes.fromByteArray(new byte[]{0, 1, 2, 3})).build());
        attributeFlags.put("Key3", EnumSet.of(EncryptionFlags.SIGN, EncryptionFlags.ENCRYPT));
        byte[] signature =
                signerRsa.calculateSignature(itemAttributes, attributeFlags, new byte[0], privKeyRsa);

        signerRsa.verifySignature(
                itemAttributes, attributeFlags, new byte[0], pubKeyRsa, ByteBuffer.wrap(signature));
    }

    @Test
    public void sigWithReadOnlySignature() throws GeneralSecurityException {
        Map<String, AttributeValue> itemAttributes = new HashMap<String, AttributeValue>();
        Map<String, Set<EncryptionFlags>> attributeFlags = new HashMap<String, Set<EncryptionFlags>>();

        itemAttributes.put("Key1", AttributeValue.builder().s("Value1").build());
        attributeFlags.put("Key1", EnumSet.of(EncryptionFlags.SIGN));
        itemAttributes.put("Key2", AttributeValue.builder().n("100").build());
        attributeFlags.put("Key2", EnumSet.of(EncryptionFlags.SIGN));
        itemAttributes.put(
                "Key3", AttributeValue.builder().b(SdkBytes.fromByteArray(new byte[]{0, 1, 2, 3})).build());
        attributeFlags.put("Key3", EnumSet.of(EncryptionFlags.SIGN, EncryptionFlags.ENCRYPT));
        byte[] signature =
                signerRsa.calculateSignature(itemAttributes, attributeFlags, new byte[0], privKeyRsa);

        signerRsa.verifySignature(
                itemAttributes,
                attributeFlags,
                new byte[0],
                pubKeyRsa,
                ByteBuffer.wrap(signature).asReadOnlyBuffer());
    }

    @Test
    public void sigNoAdMatchesEmptyAd() throws GeneralSecurityException {
        Map<String, AttributeValue> itemAttributes = new HashMap<String, AttributeValue>();
        Map<String, Set<EncryptionFlags>> attributeFlags = new HashMap<String, Set<EncryptionFlags>>();

        itemAttributes.put("Key1", AttributeValue.builder().s("Value1").build());
        attributeFlags.put("Key1", EnumSet.of(EncryptionFlags.SIGN));
        itemAttributes.put("Key2", AttributeValue.builder().n("100").build());
        attributeFlags.put("Key2", EnumSet.of(EncryptionFlags.SIGN));
        itemAttributes.put(
                "Key3", AttributeValue.builder().b(SdkBytes.fromByteArray(new byte[]{0, 1, 2, 3})).build());
        attributeFlags.put("Key3", EnumSet.of(EncryptionFlags.SIGN, EncryptionFlags.ENCRYPT));
        byte[] signature =
                signerRsa.calculateSignature(itemAttributes, attributeFlags, null, privKeyRsa);

        signerRsa.verifySignature(
                itemAttributes, attributeFlags, new byte[0], pubKeyRsa, ByteBuffer.wrap(signature));
    }

    @Test
    public void sigWithIgnoredChange() throws GeneralSecurityException {
        Map<String, AttributeValue> itemAttributes = new HashMap<String, AttributeValue>();
        Map<String, Set<EncryptionFlags>> attributeFlags = new HashMap<String, Set<EncryptionFlags>>();

        itemAttributes.put("Key1", AttributeValue.builder().s("Value1").build());
        attributeFlags.put("Key1", EnumSet.of(EncryptionFlags.SIGN));
        itemAttributes.put("Key2", AttributeValue.builder().n("100").build());
        attributeFlags.put("Key2", EnumSet.of(EncryptionFlags.SIGN));
        itemAttributes.put(
                "Key3", AttributeValue.builder().b(SdkBytes.fromByteArray(new byte[]{0, 1, 2, 3})).build());
        attributeFlags.put("Key3", EnumSet.of(EncryptionFlags.SIGN, EncryptionFlags.ENCRYPT));
        itemAttributes.put("Key4", AttributeValue.builder().s("Ignored Value").build());
        byte[] signature =
                signerRsa.calculateSignature(itemAttributes, attributeFlags, new byte[0], privKeyRsa);

        itemAttributes.put("Key4", AttributeValue.builder().s("New Ignored Value").build());
        signerRsa.verifySignature(
                itemAttributes, attributeFlags, new byte[0], pubKeyRsa, ByteBuffer.wrap(signature));
    }

    @Test
    public void sigChangedValue() throws GeneralSecurityException {
        Map<String, AttributeValue> itemAttributes = new HashMap<String, AttributeValue>();
        Map<String, Set<EncryptionFlags>> attributeFlags = new HashMap<String, Set<EncryptionFlags>>();

        itemAttributes.put("Key1", AttributeValue.builder().s("Value1").build());
        attributeFlags.put("Key1", EnumSet.of(EncryptionFlags.SIGN));
        itemAttributes.put("Key2", AttributeValue.builder().n("100").build());
        attributeFlags.put("Key2", EnumSet.of(EncryptionFlags.SIGN));
        itemAttributes.put(
                "Key3", AttributeValue.builder().b(SdkBytes.fromByteArray(new byte[]{0, 1, 2, 3})).build());
        attributeFlags.put("Key3", EnumSet.of(EncryptionFlags.SIGN, EncryptionFlags.ENCRYPT));
        byte[] signature =
                signerRsa.calculateSignature(itemAttributes, attributeFlags, new byte[0], privKeyRsa);

        itemAttributes.put("Key2", AttributeValue.builder().n("99").build());

        assertThrows(SignatureException.class, () ->
        signerRsa.verifySignature(
                itemAttributes, attributeFlags, new byte[0], pubKeyRsa, ByteBuffer.wrap(signature)));
    }

    @Test
    public void sigChangedFlag() throws GeneralSecurityException {
        Map<String, AttributeValue> itemAttributes = new HashMap<String, AttributeValue>();
        Map<String, Set<EncryptionFlags>> attributeFlags = new HashMap<String, Set<EncryptionFlags>>();

        itemAttributes.put("Key1", AttributeValue.builder().s("Value1").build());
        attributeFlags.put("Key1", EnumSet.of(EncryptionFlags.SIGN));
        itemAttributes.put("Key2", AttributeValue.builder().n("100").build());
        attributeFlags.put("Key2", EnumSet.of(EncryptionFlags.SIGN));
        itemAttributes.put(
                "Key3", AttributeValue.builder().b(SdkBytes.fromByteArray(new byte[]{0, 1, 2, 3})).build());
        attributeFlags.put("Key3", EnumSet.of(EncryptionFlags.SIGN, EncryptionFlags.ENCRYPT));
        byte[] signature =
                signerRsa.calculateSignature(itemAttributes, attributeFlags, new byte[0], privKeyRsa);

        attributeFlags.put("Key3", EnumSet.of(EncryptionFlags.SIGN));
        assertThrows(SignatureException.class, () ->
        signerRsa.verifySignature(
                itemAttributes, attributeFlags, new byte[0], pubKeyRsa, ByteBuffer.wrap(signature)));
    }

    @Test
    public void sigChangedAssociatedData() throws GeneralSecurityException {
        Map<String, AttributeValue> itemAttributes = new HashMap<String, AttributeValue>();
        Map<String, Set<EncryptionFlags>> attributeFlags = new HashMap<String, Set<EncryptionFlags>>();

        itemAttributes.put("Key1", AttributeValue.builder().s("Value1").build());
        attributeFlags.put("Key1", EnumSet.of(EncryptionFlags.SIGN));
        itemAttributes.put("Key2", AttributeValue.builder().n("100").build());
        attributeFlags.put("Key2", EnumSet.of(EncryptionFlags.SIGN));
        itemAttributes.put(
                "Key3", AttributeValue.builder().b(SdkBytes.fromByteArray(new byte[]{0, 1, 2, 3})).build());
        attributeFlags.put("Key3", EnumSet.of(EncryptionFlags.SIGN, EncryptionFlags.ENCRYPT));
        byte[] signature =
                signerRsa.calculateSignature(itemAttributes, attributeFlags, new byte[0], privKeyRsa);

        assertThrows(SignatureException.class, () ->
        signerRsa.verifySignature(
                itemAttributes,
                attributeFlags,
                new byte[]{1, 2, 3},
                pubKeyRsa,
                ByteBuffer.wrap(signature)));
    }

    @Test
    public void sigEcdsa() throws GeneralSecurityException {
        Map<String, AttributeValue> itemAttributes = new HashMap<String, AttributeValue>();
        Map<String, Set<EncryptionFlags>> attributeFlags = new HashMap<String, Set<EncryptionFlags>>();

        itemAttributes.put("Key1", AttributeValue.builder().s("Value1").build());
        attributeFlags.put("Key1", EnumSet.of(EncryptionFlags.SIGN));
        itemAttributes.put("Key2", AttributeValue.builder().n("100").build());
        attributeFlags.put("Key2", EnumSet.of(EncryptionFlags.SIGN));
        itemAttributes.put(
                "Key3", AttributeValue.builder().b(SdkBytes.fromByteArray(new byte[]{0, 1, 2, 3})).build());
        attributeFlags.put("Key3", EnumSet.of(EncryptionFlags.SIGN));
        byte[] signature =
                signerEcdsa.calculateSignature(itemAttributes, attributeFlags, new byte[0], privKeyEcdsa);

        signerEcdsa.verifySignature(
                itemAttributes, attributeFlags, new byte[0], pubKeyEcdsa, ByteBuffer.wrap(signature));
    }

    @Test
    public void sigEcdsaWithReadOnlySignature() throws GeneralSecurityException {
        Map<String, AttributeValue> itemAttributes = new HashMap<String, AttributeValue>();
        Map<String, Set<EncryptionFlags>> attributeFlags = new HashMap<String, Set<EncryptionFlags>>();

        itemAttributes.put("Key1", AttributeValue.builder().s("Value1").build());
        attributeFlags.put("Key1", EnumSet.of(EncryptionFlags.SIGN));
        itemAttributes.put("Key2", AttributeValue.builder().n("100").build());
        attributeFlags.put("Key2", EnumSet.of(EncryptionFlags.SIGN));
        itemAttributes.put(
                "Key3", AttributeValue.builder().b(SdkBytes.fromByteArray(new byte[]{0, 1, 2, 3})).build());
        attributeFlags.put("Key3", EnumSet.of(EncryptionFlags.SIGN));
        byte[] signature =
                signerEcdsa.calculateSignature(itemAttributes, attributeFlags, new byte[0], privKeyEcdsa);

        signerEcdsa.verifySignature(
                itemAttributes,
                attributeFlags,
                new byte[0],
                pubKeyEcdsa,
                ByteBuffer.wrap(signature).asReadOnlyBuffer());
    }

    @Test
    public void sigEcdsaNoAdMatchesEmptyAd() throws GeneralSecurityException {
        Map<String, AttributeValue> itemAttributes = new HashMap<String, AttributeValue>();
        Map<String, Set<EncryptionFlags>> attributeFlags = new HashMap<String, Set<EncryptionFlags>>();

        itemAttributes.put("Key1", AttributeValue.builder().s("Value1").build());
        attributeFlags.put("Key1", EnumSet.of(EncryptionFlags.SIGN));
        itemAttributes.put("Key2", AttributeValue.builder().n("100").build());
        attributeFlags.put("Key2", EnumSet.of(EncryptionFlags.SIGN));
        itemAttributes.put(
                "Key3", AttributeValue.builder().b(SdkBytes.fromByteArray(new byte[]{0, 1, 2, 3})).build());
        attributeFlags.put("Key3", EnumSet.of(EncryptionFlags.SIGN));
        byte[] signature =
                signerEcdsa.calculateSignature(itemAttributes, attributeFlags, null, privKeyEcdsa);

        signerEcdsa.verifySignature(
                itemAttributes, attributeFlags, new byte[0], pubKeyEcdsa, ByteBuffer.wrap(signature));
    }

    @Test
    public void sigEcdsaWithIgnoredChange() throws GeneralSecurityException {
        Map<String, AttributeValue> itemAttributes = new HashMap<String, AttributeValue>();
        Map<String, Set<EncryptionFlags>> attributeFlags = new HashMap<String, Set<EncryptionFlags>>();

        itemAttributes.put("Key1", AttributeValue.builder().s("Value1").build());
        attributeFlags.put("Key1", EnumSet.of(EncryptionFlags.SIGN));
        itemAttributes.put("Key2", AttributeValue.builder().n("100").build());
        attributeFlags.put("Key2", EnumSet.of(EncryptionFlags.SIGN));
        itemAttributes.put(
                "Key3", AttributeValue.builder().b(SdkBytes.fromByteArray(new byte[]{0, 1, 2, 3})).build());
        attributeFlags.put("Key3", EnumSet.of(EncryptionFlags.SIGN));
        itemAttributes.put("Key4", AttributeValue.builder().s("Ignored Value").build());
        byte[] signature =
                signerEcdsa.calculateSignature(itemAttributes, attributeFlags, new byte[0], privKeyEcdsa);

        itemAttributes.put("Key4", AttributeValue.builder().s("New Ignored Value").build());
        signerEcdsa.verifySignature(
                itemAttributes, attributeFlags, new byte[0], pubKeyEcdsa, ByteBuffer.wrap(signature));
    }

    @Test
    public void sigEcdsaChangedValue() throws GeneralSecurityException {
        Map<String, AttributeValue> itemAttributes = new HashMap<String, AttributeValue>();
        Map<String, Set<EncryptionFlags>> attributeFlags = new HashMap<String, Set<EncryptionFlags>>();

        itemAttributes.put("Key1", AttributeValue.builder().s("Value1").build());
        attributeFlags.put("Key1", EnumSet.of(EncryptionFlags.SIGN));
        itemAttributes.put("Key2", AttributeValue.builder().n("100").build());
        attributeFlags.put("Key2", EnumSet.of(EncryptionFlags.SIGN));
        itemAttributes.put(
                "Key3", AttributeValue.builder().b(SdkBytes.fromByteArray(new byte[]{0, 1, 2, 3})).build());
        attributeFlags.put("Key3", EnumSet.of(EncryptionFlags.SIGN));
        byte[] signature =
                signerEcdsa.calculateSignature(itemAttributes, attributeFlags, new byte[0], privKeyEcdsa);

        itemAttributes.put("Key2", AttributeValue.builder().n("99").build());
        assertThrows(SignatureException.class, () ->
                signerEcdsa.verifySignature(
                        itemAttributes, attributeFlags, new byte[0], pubKeyEcdsa, ByteBuffer.wrap(signature)));
    }

    @Test
    public void sigEcdsaChangedAssociatedData() throws GeneralSecurityException {
        Map<String, AttributeValue> itemAttributes = new HashMap<String, AttributeValue>();
        Map<String, Set<EncryptionFlags>> attributeFlags = new HashMap<String, Set<EncryptionFlags>>();

        itemAttributes.put("Key1", AttributeValue.builder().s("Value1").build());
        attributeFlags.put("Key1", EnumSet.of(EncryptionFlags.SIGN));
        itemAttributes.put("Key2", AttributeValue.builder().n("100").build());
        attributeFlags.put("Key2", EnumSet.of(EncryptionFlags.SIGN));
        itemAttributes.put(
                "Key3", AttributeValue.builder().b(SdkBytes.fromByteArray(new byte[]{0, 1, 2, 3})).build());
        attributeFlags.put("Key3", EnumSet.of(EncryptionFlags.SIGN));
        byte[] signature =
                signerEcdsa.calculateSignature(itemAttributes, attributeFlags, new byte[0], privKeyEcdsa);

        assertThrows(SignatureException.class, () ->
                signerEcdsa.verifySignature(
                        itemAttributes,
                        attributeFlags,
                        new byte[]{1, 2, 3},
                        pubKeyEcdsa,
                        ByteBuffer.wrap(signature)));
    }
}
