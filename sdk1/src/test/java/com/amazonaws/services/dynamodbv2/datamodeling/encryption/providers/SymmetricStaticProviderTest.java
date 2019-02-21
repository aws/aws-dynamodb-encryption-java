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
package com.amazonaws.services.dynamodbv2.datamodeling.encryption.providers;

import com.amazonaws.services.dynamodbv2.datamodeling.encryption.EncryptionContext;
import com.amazonaws.services.dynamodbv2.datamodeling.encryption.materials.EncryptionMaterials;
import com.amazonaws.services.dynamodbv2.datamodeling.internal.Utils;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static org.testng.AssertJUnit.assertEquals;
import static org.testng.AssertJUnit.assertNull;
import static org.testng.AssertJUnit.assertTrue;

public class SymmetricStaticProviderTest {
    private static SecretKey encryptionKey;
    private static SecretKey macKey;
    private static KeyPair sigPair;
    private Map<String, String> description;
    private EncryptionContext ctx;

    @BeforeClass
    public static void setUpClass() throws Exception {
        KeyPairGenerator rsaGen = KeyPairGenerator.getInstance("RSA");
        rsaGen.initialize(2048, Utils.getRng());
        sigPair = rsaGen.generateKeyPair();

        KeyGenerator macGen = KeyGenerator.getInstance("HmacSHA256");
        macGen.init(256, Utils.getRng());
        macKey = macGen.generateKey();

        KeyGenerator aesGen = KeyGenerator.getInstance("AES");
        aesGen.init(128, Utils.getRng());
        encryptionKey = aesGen.generateKey();
    }

    @BeforeMethod
    public void setUp() {
        description = new HashMap<String, String>();
        description.put("TestKey", "test value");
        description = Collections.unmodifiableMap(description);
        ctx = new EncryptionContext.Builder().build();
    }

    @Test
    public void simpleMac() {
        SymmetricStaticProvider prov = new SymmetricStaticProvider(
                encryptionKey, macKey, Collections.<String, String>emptyMap());
        assertEquals(encryptionKey, prov.getEncryptionMaterials(ctx).getEncryptionKey());
        assertEquals(macKey, prov.getEncryptionMaterials(ctx).getSigningKey());

        assertEquals(
                encryptionKey,
                prov.getDecryptionMaterials(ctx(Collections.<String, String>emptyMap()))
                        .getDecryptionKey());
        assertEquals(
                macKey,
                prov.getDecryptionMaterials(ctx(Collections.<String, String>emptyMap()))
                        .getVerificationKey());
    }

    @Test
    public void simpleSig() {
        SymmetricStaticProvider prov = new SymmetricStaticProvider(encryptionKey, sigPair, Collections.<String, String>emptyMap());
        assertEquals(encryptionKey, prov.getEncryptionMaterials(ctx).getEncryptionKey());
        assertEquals(sigPair.getPrivate(), prov.getEncryptionMaterials(ctx).getSigningKey());

        assertEquals(encryptionKey, prov.getDecryptionMaterials(ctx(Collections.<String, String>emptyMap())).getDecryptionKey());
        assertEquals(
                sigPair.getPublic(),
                prov.getDecryptionMaterials(ctx(Collections.<String, String>emptyMap()))
                        .getVerificationKey());
    }

    @Test
    public void equalDescMac() {

        SymmetricStaticProvider prov = new SymmetricStaticProvider(encryptionKey, macKey, description);
        assertEquals(encryptionKey, prov.getEncryptionMaterials(ctx).getEncryptionKey());
        assertEquals(macKey, prov.getEncryptionMaterials(ctx).getSigningKey());
        assertTrue(prov.getEncryptionMaterials(ctx).getMaterialDescription().entrySet().containsAll(description.entrySet()));

        assertEquals(encryptionKey, prov.getDecryptionMaterials(ctx(description)).getDecryptionKey());
        assertEquals(macKey, prov.getDecryptionMaterials(ctx(description)).getVerificationKey());

    }

    @Test
    public void supersetDescMac() {
        SymmetricStaticProvider prov = new SymmetricStaticProvider(encryptionKey, macKey, description);
        assertEquals(encryptionKey, prov.getEncryptionMaterials(ctx).getEncryptionKey());
        assertEquals(macKey, prov.getEncryptionMaterials(ctx).getSigningKey());
        assertTrue(prov.getEncryptionMaterials(ctx).getMaterialDescription().entrySet().containsAll(description.entrySet()));

        Map<String, String> superSet = new HashMap<String, String>(description);
        superSet.put("NewValue", "super!");

        assertEquals(encryptionKey, prov.getDecryptionMaterials(ctx(superSet)).getDecryptionKey());
        assertEquals(macKey, prov.getDecryptionMaterials(ctx(superSet)).getVerificationKey());
    }

    @Test
    public void subsetDescMac() {
        SymmetricStaticProvider prov = new SymmetricStaticProvider(encryptionKey, macKey, description);
        assertEquals(encryptionKey, prov.getEncryptionMaterials(ctx).getEncryptionKey());
        assertEquals(macKey, prov.getEncryptionMaterials(ctx).getSigningKey());
        assertTrue(prov.getEncryptionMaterials(ctx).getMaterialDescription().entrySet().containsAll(description.entrySet()));

        assertNull(prov.getDecryptionMaterials(ctx(Collections.<String, String>emptyMap())));
    }

    @Test
    public void noMatchDescMac() {
        SymmetricStaticProvider prov = new SymmetricStaticProvider(encryptionKey, macKey, description);
        assertEquals(encryptionKey, prov.getEncryptionMaterials(ctx).getEncryptionKey());
        assertEquals(macKey, prov.getEncryptionMaterials(ctx).getSigningKey());
        assertTrue(prov.getEncryptionMaterials(ctx).getMaterialDescription().entrySet().containsAll(description.entrySet()));

        Map<String, String> noMatch = new HashMap<String, String>();
        noMatch.put("NewValue", "no match!");

        assertNull(prov.getDecryptionMaterials(ctx(noMatch)));
    }

    @Test
    public void testRefresh() {
        // This does nothing, make sure we don't throw and exception.
        SymmetricStaticProvider prov = new SymmetricStaticProvider(encryptionKey, macKey, description);
        prov.refresh();
    }

    @SuppressWarnings("unused")
    private static EncryptionContext ctx(EncryptionMaterials mat) {
        return ctx(mat.getMaterialDescription());
    }

    private static EncryptionContext ctx(Map<String, String> desc) {
        return new EncryptionContext.Builder()
                .withMaterialDescription(desc).build();
    }
}
