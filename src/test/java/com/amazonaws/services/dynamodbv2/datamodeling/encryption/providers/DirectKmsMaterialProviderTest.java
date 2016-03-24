/*
 * Copyright 2014 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * 
 * Licensed under the Apache License, Version 2.0 (the "License"). You may not use this file except
 * in compliance with the License. A copy of the License is located at
 * 
 * http://aws.amazon.com/apache2.0
 * 
 * or in the "license" file accompanying this file. This file is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */
package com.amazonaws.services.dynamodbv2.datamodeling.encryption.providers;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.SecretKey;

import org.junit.Before;
import org.junit.Test;

import com.amazonaws.services.dynamodbv2.datamodeling.encryption.EncryptionContext;
import com.amazonaws.services.dynamodbv2.datamodeling.encryption.materials.DecryptionMaterials;
import com.amazonaws.services.dynamodbv2.datamodeling.encryption.materials.EncryptionMaterials;
import com.amazonaws.services.dynamodbv2.datamodeling.encryption.materials.WrappedRawMaterials;
import com.amazonaws.services.dynamodbv2.model.AttributeValue;
import com.amazonaws.services.dynamodbv2.testing.FakeKMS;
import com.amazonaws.util.Base64;

public class DirectKmsMaterialProviderTest {
    private FakeKMS kms;
    private String keyId;
    private Map<String, String> description;
    private EncryptionContext ctx;

    @Before
    public void setUp() {
        description = new HashMap<String, String>();
        description.put("TestKey", "test value");
        description = Collections.unmodifiableMap(description);
        ctx = new EncryptionContext.Builder().build();
        kms = new FakeKMS();
        keyId = kms.createKey().getKeyMetadata().getKeyId();
    }

    @Test
    public void simple() throws GeneralSecurityException {
        DirectKmsMaterialProvider prov = new DirectKmsMaterialProvider(kms, keyId);

        EncryptionMaterials eMat = prov.getEncryptionMaterials(ctx);
        SecretKey encryptionKey = eMat.getEncryptionKey();
        assertNotNull(encryptionKey);
        Key signingKey = eMat.getSigningKey();
        assertNotNull(signingKey);

        DecryptionMaterials dMat = prov.getDecryptionMaterials(ctx(eMat));
        assertEquals(encryptionKey, dMat.getDecryptionKey());
        assertEquals(signingKey, dMat.getVerificationKey());

        String expectedEncAlg = encryptionKey.getAlgorithm() + "/"
                + (encryptionKey.getEncoded().length * 8);
        String expectedSigAlg = signingKey.getAlgorithm() + "/"
                + (signingKey.getEncoded().length * 8);

        Map<String, String> kmsCtx = kms.getSingleEc();
        assertEquals(expectedEncAlg,
                kmsCtx.get("*" + WrappedRawMaterials.CONTENT_KEY_ALGORITHM + "*"));
        assertEquals(expectedSigAlg, kmsCtx.get("*amzn-ddb-sig-alg*"));
    }

    @Test
    public void simpleWithKmsEc() throws GeneralSecurityException {
        DirectKmsMaterialProvider prov = new DirectKmsMaterialProvider(kms, keyId);

        Map<String, AttributeValue> attrVals = new HashMap<String, AttributeValue>();
        attrVals.put("hk", new AttributeValue("HashKeyValue"));
        attrVals.put("rk", new AttributeValue("RangeKeyValue"));

        ctx = new EncryptionContext.Builder().withHashKeyName("hk").withRangeKeyName("rk")
                .withTableName("KmsTableName").withAttributeValues(attrVals).build();
        EncryptionMaterials eMat = prov.getEncryptionMaterials(ctx);
        SecretKey encryptionKey = eMat.getEncryptionKey();
        assertNotNull(encryptionKey);
        Key signingKey = eMat.getSigningKey();
        assertNotNull(signingKey);
        Map<String, String> kmsCtx = kms.getSingleEc();
        assertEquals("HashKeyValue", kmsCtx.get("hk"));
        assertEquals("RangeKeyValue", kmsCtx.get("rk"));
        assertEquals("KmsTableName", kmsCtx.get("*aws-kms-table*"));

        EncryptionContext dCtx = new EncryptionContext.Builder(ctx(eMat)).withHashKeyName("hk")
                .withRangeKeyName("rk").withTableName("KmsTableName").withAttributeValues(attrVals)
                .build();

        DecryptionMaterials dMat = prov.getDecryptionMaterials(dCtx);
        assertEquals(encryptionKey, dMat.getDecryptionKey());
        assertEquals(signingKey, dMat.getVerificationKey());
    }

    @Test
    public void simpleWithKmsEc2() throws GeneralSecurityException {
        DirectKmsMaterialProvider prov = new DirectKmsMaterialProvider(kms, keyId);

        Map<String, AttributeValue> attrVals = new HashMap<String, AttributeValue>();
        attrVals.put("hk", new AttributeValue().withN("10"));
        attrVals.put("rk", new AttributeValue().withN("20"));

        ctx = new EncryptionContext.Builder().withHashKeyName("hk").withRangeKeyName("rk")
                .withTableName("KmsTableName").withAttributeValues(attrVals).build();
        EncryptionMaterials eMat = prov.getEncryptionMaterials(ctx);
        SecretKey encryptionKey = eMat.getEncryptionKey();
        assertNotNull(encryptionKey);
        Key signingKey = eMat.getSigningKey();
        assertNotNull(signingKey);
        Map<String, String> kmsCtx = kms.getSingleEc();
        assertEquals("10", kmsCtx.get("hk"));
        assertEquals("20", kmsCtx.get("rk"));
        assertEquals("KmsTableName", kmsCtx.get("*aws-kms-table*"));

        EncryptionContext dCtx = new EncryptionContext.Builder(ctx(eMat)).withHashKeyName("hk")
                .withRangeKeyName("rk").withTableName("KmsTableName").withAttributeValues(attrVals)
                .build();

        DecryptionMaterials dMat = prov.getDecryptionMaterials(dCtx);
        assertEquals(encryptionKey, dMat.getDecryptionKey());
        assertEquals(signingKey, dMat.getVerificationKey());
    }

    @Test
    public void simpleWithKmsEc3() throws GeneralSecurityException {
        DirectKmsMaterialProvider prov = new DirectKmsMaterialProvider(kms, keyId);

        Map<String, AttributeValue> attrVals = new HashMap<String, AttributeValue>();
        attrVals.put("hk",
                new AttributeValue().withB(ByteBuffer.wrap("Foo".getBytes(StandardCharsets.UTF_8))));
        attrVals.put("rk",
                new AttributeValue().withB(ByteBuffer.wrap("Bar".getBytes(StandardCharsets.UTF_8))));

        ctx = new EncryptionContext.Builder().withHashKeyName("hk").withRangeKeyName("rk")
                .withTableName("KmsTableName").withAttributeValues(attrVals).build();
        EncryptionMaterials eMat = prov.getEncryptionMaterials(ctx);
        SecretKey encryptionKey = eMat.getEncryptionKey();
        assertNotNull(encryptionKey);
        Key signingKey = eMat.getSigningKey();
        assertNotNull(signingKey);
        assertNotNull(signingKey);
        Map<String, String> kmsCtx = kms.getSingleEc();
        assertEquals(Base64.encodeAsString("Foo".getBytes(StandardCharsets.UTF_8)),
                kmsCtx.get("hk"));
        assertEquals(Base64.encodeAsString("Bar".getBytes(StandardCharsets.UTF_8)),
                kmsCtx.get("rk"));
        assertEquals("KmsTableName", kmsCtx.get("*aws-kms-table*"));

        EncryptionContext dCtx = new EncryptionContext.Builder(ctx(eMat)).withHashKeyName("hk")
                .withRangeKeyName("rk").withTableName("KmsTableName").withAttributeValues(attrVals)
                .build();

        DecryptionMaterials dMat = prov.getDecryptionMaterials(dCtx);
        assertEquals(encryptionKey, dMat.getDecryptionKey());
        assertEquals(signingKey, dMat.getVerificationKey());
    }

    @Test
    public void randomEnvelopeKeys() throws GeneralSecurityException {
        DirectKmsMaterialProvider prov = new DirectKmsMaterialProvider(kms, keyId);

        EncryptionMaterials eMat = prov.getEncryptionMaterials(ctx);
        SecretKey encryptionKey = eMat.getEncryptionKey();
        assertNotNull(encryptionKey);

        EncryptionMaterials eMat2 = prov.getEncryptionMaterials(ctx);
        SecretKey encryptionKey2 = eMat2.getEncryptionKey();

        assertFalse("Envelope keys must be different", encryptionKey.equals(encryptionKey2));
    }

    @Test
    public void testRefresh() {
        // This does nothing, make sure we don't throw and exception.
        DirectKmsMaterialProvider prov = new DirectKmsMaterialProvider(kms, keyId);
        prov.refresh();
    }

    @Test
    public void explicitContentKeyAlgorithm() throws GeneralSecurityException {
        Map<String, String> desc = new HashMap<String, String>();
        desc.put(WrappedRawMaterials.CONTENT_KEY_ALGORITHM, "AES");

        DirectKmsMaterialProvider prov = new DirectKmsMaterialProvider(kms, keyId, desc);

        EncryptionMaterials eMat = prov.getEncryptionMaterials(ctx);
        SecretKey encryptionKey = eMat.getEncryptionKey();
        assertNotNull(encryptionKey);

        DecryptionMaterials dMat = prov.getDecryptionMaterials(ctx(eMat));
        assertEquals("AES",
                eMat.getMaterialDescription().get(WrappedRawMaterials.CONTENT_KEY_ALGORITHM));
        assertEquals(encryptionKey, dMat.getDecryptionKey());
    }

    @Test
    public void explicitContentKeyLength128() throws GeneralSecurityException {
        Map<String, String> desc = new HashMap<String, String>();
        desc.put(WrappedRawMaterials.CONTENT_KEY_ALGORITHM, "AES/128");

        DirectKmsMaterialProvider prov = new DirectKmsMaterialProvider(kms, keyId, desc);

        EncryptionMaterials eMat = prov.getEncryptionMaterials(ctx);
        SecretKey encryptionKey = eMat.getEncryptionKey();
        assertNotNull(encryptionKey);
        assertEquals(16, encryptionKey.getEncoded().length); // 128 Bits

        DecryptionMaterials dMat = prov.getDecryptionMaterials(ctx(eMat));
        assertEquals("AES/128",
                eMat.getMaterialDescription().get(WrappedRawMaterials.CONTENT_KEY_ALGORITHM));
        assertEquals("AES", eMat.getEncryptionKey().getAlgorithm());
        assertEquals(encryptionKey, dMat.getDecryptionKey());
    }

    @Test
    public void explicitContentKeyLength256() throws GeneralSecurityException {
        Map<String, String> desc = new HashMap<String, String>();
        desc.put(WrappedRawMaterials.CONTENT_KEY_ALGORITHM, "AES/256");

        DirectKmsMaterialProvider prov = new DirectKmsMaterialProvider(kms, keyId, desc);

        EncryptionMaterials eMat = prov.getEncryptionMaterials(ctx);
        SecretKey encryptionKey = eMat.getEncryptionKey();
        assertNotNull(encryptionKey);
        assertEquals(32, encryptionKey.getEncoded().length); // 256 Bits

        DecryptionMaterials dMat = prov.getDecryptionMaterials(ctx(eMat));
        assertEquals("AES/256",
                eMat.getMaterialDescription().get(WrappedRawMaterials.CONTENT_KEY_ALGORITHM));
        assertEquals("AES", eMat.getEncryptionKey().getAlgorithm());
        assertEquals(encryptionKey, dMat.getDecryptionKey());
    }

    private static EncryptionContext ctx(EncryptionMaterials mat) {
        return new EncryptionContext.Builder()
                .withMaterialDescription(mat.getMaterialDescription()).build();
    }
}
