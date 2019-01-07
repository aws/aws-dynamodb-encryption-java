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
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;

import static org.testng.AssertJUnit.assertEquals;
import static org.testng.AssertJUnit.assertTrue;

public class SymmetricRawMaterialsTest {
    private static SecretKey encryptionKey;
    private static SecretKey macKey;
    private static KeyPair sigPair;
    private static SecureRandom rnd;
    private Map<String, String> description;

    @BeforeClass
    public static void setUpClass() throws NoSuchAlgorithmException {
        rnd = new SecureRandom();
        KeyPairGenerator rsaGen = KeyPairGenerator.getInstance("RSA");
        rsaGen.initialize(2048, rnd);
        sigPair = rsaGen.generateKeyPair();

        KeyGenerator aesGen = KeyGenerator.getInstance("AES");
        aesGen.init(128, rnd);
        encryptionKey = aesGen.generateKey();

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
    public void macNoDescription() throws NoSuchAlgorithmException {
        SymmetricRawMaterials mat = new SymmetricRawMaterials(encryptionKey, macKey);
        assertEquals(encryptionKey, mat.getEncryptionKey());
        assertEquals(encryptionKey, mat.getDecryptionKey());
        assertEquals(macKey, mat.getSigningKey());
        assertEquals(macKey, mat.getVerificationKey());
        assertTrue(mat.getMaterialDescription().isEmpty());
    }

    @Test
    public void macWithDescription() throws NoSuchAlgorithmException {
        SymmetricRawMaterials mat = new SymmetricRawMaterials(encryptionKey, macKey, description);
        assertEquals(encryptionKey, mat.getEncryptionKey());
        assertEquals(encryptionKey, mat.getDecryptionKey());
        assertEquals(macKey, mat.getSigningKey());
        assertEquals(macKey, mat.getVerificationKey());
        assertEquals(description, mat.getMaterialDescription());
        assertEquals("test value", mat.getMaterialDescription().get("TestKey"));
    }

    @Test
    public void sigNoDescription() throws NoSuchAlgorithmException {
        SymmetricRawMaterials mat = new SymmetricRawMaterials(encryptionKey, sigPair);
        assertEquals(encryptionKey, mat.getEncryptionKey());
        assertEquals(encryptionKey, mat.getDecryptionKey());
        assertEquals(sigPair.getPrivate(), mat.getSigningKey());
        assertEquals(sigPair.getPublic(), mat.getVerificationKey());
        assertTrue(mat.getMaterialDescription().isEmpty());
    }

    @Test
    public void sigWithDescription() throws NoSuchAlgorithmException {
        SymmetricRawMaterials mat = new SymmetricRawMaterials(encryptionKey, sigPair, description);
        assertEquals(encryptionKey, mat.getEncryptionKey());
        assertEquals(encryptionKey, mat.getDecryptionKey());
        assertEquals(sigPair.getPrivate(), mat.getSigningKey());
        assertEquals(sigPair.getPublic(), mat.getVerificationKey());
        assertEquals(description, mat.getMaterialDescription());
        assertEquals("test value", mat.getMaterialDescription().get("TestKey"));
    }
}
