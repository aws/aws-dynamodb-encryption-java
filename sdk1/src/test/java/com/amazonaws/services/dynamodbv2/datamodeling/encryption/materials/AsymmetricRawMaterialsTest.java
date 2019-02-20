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
package com.amazonaws.services.dynamodbv2.datamodeling.encryption.materials;

import org.testng.annotations.BeforeMethod;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;

import static org.testng.AssertJUnit.assertEquals;
import static org.testng.AssertJUnit.assertFalse;

public class AsymmetricRawMaterialsTest {
    private static SecureRandom rnd;
    private static KeyPair encryptionPair;
    private static SecretKey macKey;
    private static KeyPair sigPair;
    private Map<String, String> description;

    @BeforeClass
    public static void setUpClass() throws NoSuchAlgorithmException {
        rnd = new SecureRandom();
        KeyPairGenerator rsaGen = KeyPairGenerator.getInstance("RSA");
        rsaGen.initialize(2048, rnd);
        encryptionPair = rsaGen.generateKeyPair();
        sigPair = rsaGen.generateKeyPair();

        KeyGenerator macGen = KeyGenerator.getInstance("HmacSHA256");
        macGen.init(256, rnd);
        macKey = macGen.generateKey();
    }

    @BeforeMethod
    public void setUp() {
        description = new HashMap<String, String>();
        description.put("TestKey", "test value");
    }

    @Test
    public void macNoDescription() throws GeneralSecurityException {
        AsymmetricRawMaterials matEncryption = new AsymmetricRawMaterials(encryptionPair, macKey);
        assertEquals(macKey, matEncryption.getSigningKey());
        assertEquals(macKey, matEncryption.getVerificationKey());
        assertFalse(matEncryption.getMaterialDescription().isEmpty());

        SecretKey envelopeKey = matEncryption.getEncryptionKey();
        assertEquals(envelopeKey, matEncryption.getDecryptionKey());

        AsymmetricRawMaterials matDecryption = new AsymmetricRawMaterials(encryptionPair, macKey, matEncryption.getMaterialDescription());
        assertEquals(macKey, matDecryption.getSigningKey());
        assertEquals(macKey, matDecryption.getVerificationKey());
        assertEquals(envelopeKey, matDecryption.getEncryptionKey());
        assertEquals(envelopeKey, matDecryption.getDecryptionKey());
    }

    @Test
    public void macWithDescription() throws GeneralSecurityException {
        AsymmetricRawMaterials matEncryption = new AsymmetricRawMaterials(encryptionPair, macKey, description);
        assertEquals(macKey, matEncryption.getSigningKey());
        assertEquals(macKey, matEncryption.getVerificationKey());
        assertFalse(matEncryption.getMaterialDescription().isEmpty());
        assertEquals("test value", matEncryption.getMaterialDescription().get("TestKey"));

        SecretKey envelopeKey = matEncryption.getEncryptionKey();
        assertEquals(envelopeKey, matEncryption.getDecryptionKey());

        AsymmetricRawMaterials matDecryption = new AsymmetricRawMaterials(encryptionPair, macKey, matEncryption.getMaterialDescription());
        assertEquals(macKey, matDecryption.getSigningKey());
        assertEquals(macKey, matDecryption.getVerificationKey());
        assertEquals(envelopeKey, matDecryption.getEncryptionKey());
        assertEquals(envelopeKey, matDecryption.getDecryptionKey());
        assertEquals("test value", matDecryption.getMaterialDescription().get("TestKey"));
    }

    @Test
    public void sigNoDescription() throws GeneralSecurityException {
        AsymmetricRawMaterials matEncryption = new AsymmetricRawMaterials(encryptionPair, sigPair);
        assertEquals(sigPair.getPrivate(), matEncryption.getSigningKey());
        assertEquals(sigPair.getPublic(), matEncryption.getVerificationKey());
        assertFalse(matEncryption.getMaterialDescription().isEmpty());

        SecretKey envelopeKey = matEncryption.getEncryptionKey();
        assertEquals(envelopeKey, matEncryption.getDecryptionKey());

        AsymmetricRawMaterials matDecryption = new AsymmetricRawMaterials(encryptionPair, sigPair, matEncryption.getMaterialDescription());
        assertEquals(sigPair.getPrivate(), matDecryption.getSigningKey());
        assertEquals(sigPair.getPublic(), matDecryption.getVerificationKey());
        assertEquals(envelopeKey, matDecryption.getEncryptionKey());
        assertEquals(envelopeKey, matDecryption.getDecryptionKey());
    }

    @Test
    public void sigWithDescription() throws GeneralSecurityException {
        AsymmetricRawMaterials matEncryption = new AsymmetricRawMaterials(encryptionPair, sigPair, description);
        assertEquals(sigPair.getPrivate(), matEncryption.getSigningKey());
        assertEquals(sigPair.getPublic(), matEncryption.getVerificationKey());
        assertFalse(matEncryption.getMaterialDescription().isEmpty());
        assertEquals("test value", matEncryption.getMaterialDescription().get("TestKey"));

        SecretKey envelopeKey = matEncryption.getEncryptionKey();
        assertEquals(envelopeKey, matEncryption.getDecryptionKey());

        AsymmetricRawMaterials matDecryption = new AsymmetricRawMaterials(encryptionPair, sigPair, matEncryption.getMaterialDescription());
        assertEquals(sigPair.getPrivate(), matDecryption.getSigningKey());
        assertEquals(sigPair.getPublic(), matDecryption.getVerificationKey());
        assertEquals(envelopeKey, matDecryption.getEncryptionKey());
        assertEquals(envelopeKey, matDecryption.getDecryptionKey());
        assertEquals("test value", matDecryption.getMaterialDescription().get("TestKey"));
    }
}
