/*
 * Copyright 2015 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

import com.amazonaws.services.dynamodbv2.AmazonDynamoDB;
import com.amazonaws.services.dynamodbv2.datamodeling.encryption.DynamoDBEncryptor;
import com.amazonaws.services.dynamodbv2.datamodeling.encryption.EncryptionContext;
import com.amazonaws.services.dynamodbv2.datamodeling.encryption.materials.DecryptionMaterials;
import com.amazonaws.services.dynamodbv2.datamodeling.encryption.materials.EncryptionMaterials;
import com.amazonaws.services.dynamodbv2.datamodeling.encryption.providers.store.MetaStore;
import com.amazonaws.services.dynamodbv2.datamodeling.encryption.providers.store.ProviderStore;
import com.amazonaws.services.dynamodbv2.local.embedded.DynamoDBEmbedded;
import com.amazonaws.services.dynamodbv2.model.AttributeValue;
import com.amazonaws.services.dynamodbv2.model.ProvisionedThroughput;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static org.testng.AssertJUnit.assertEquals;
import static org.testng.AssertJUnit.assertFalse;
import static org.testng.AssertJUnit.assertNull;
import static org.testng.AssertJUnit.assertTrue;

public class MostRecentProviderTests {
    private static final String TABLE_NAME = "keystoreTable";
    private static final String MATERIAL_NAME = "material";
    private static final String MATERIAL_PARAM = "materialName";
    private static final SecretKey AES_KEY = new SecretKeySpec(new byte[]{0,
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}, "AES");
    private static final SecretKey HMAC_KEY = new SecretKeySpec(new byte[]{0,
            1, 2, 3, 4, 5, 6, 7}, "HmacSHA256");
    private static final EncryptionMaterialsProvider BASE_PROVIDER = new SymmetricStaticProvider(AES_KEY, HMAC_KEY);
    private static final DynamoDBEncryptor ENCRYPTOR = DynamoDBEncryptor.getInstance(BASE_PROVIDER);

    private AmazonDynamoDB client;
    private Map<String, Integer> methodCalls;
    private ProviderStore store;
    private EncryptionContext ctx;

    @BeforeMethod
    public void setup() {
        methodCalls = new HashMap<String, Integer>();
        client = instrument(DynamoDBEmbedded.create(), AmazonDynamoDB.class, methodCalls);
        MetaStore.createTable(client, TABLE_NAME, new ProvisionedThroughput(1L, 1L));
        store = new MetaStore(client, TABLE_NAME, ENCRYPTOR);
        ctx = new EncryptionContext.Builder().build();
        methodCalls.clear();
    }

    @Test
    public void constructor() {
        final MostRecentProvider prov = new MostRecentProvider(store, MATERIAL_NAME, 100);
        assertEquals(MATERIAL_NAME, prov.getMaterialName());
        assertEquals(100, prov.getTtlInMills());
        assertEquals(-1, prov.getCurrentVersion());
        assertEquals(0, prov.getLastUpdated());
    }

    @Test
    public void singleVersion() throws InterruptedException {
        final MostRecentProvider prov = new MostRecentProvider(store, MATERIAL_NAME, 500);
        assertNull(methodCalls.get("putItem"));
        final EncryptionMaterials eMat1 = prov.getEncryptionMaterials(ctx);
        // It's a new provider, so we see a single putItem
        assertEquals(1, (int) methodCalls.getOrDefault("putItem", 0));
        methodCalls.clear();
        // Ensure the cache is working
        final EncryptionMaterials eMat2 = prov.getEncryptionMaterials(ctx);
        assertTrue(methodCalls.isEmpty());
        assertEquals(0, store.getVersionFromMaterialDescription(eMat1.getMaterialDescription()));
        assertEquals(0, store.getVersionFromMaterialDescription(eMat2.getMaterialDescription()));
        // Let the TTL be exceeded
        Thread.sleep(500);
        final EncryptionMaterials eMat3 = prov.getEncryptionMaterials(ctx);
        assertEquals(1, methodCalls.size());
        assertEquals(1, (int) methodCalls.getOrDefault("query", 0)); // To find current version
        assertEquals(0, store.getVersionFromMaterialDescription(eMat3.getMaterialDescription()));

        assertEquals(eMat1.getSigningKey(), eMat2.getSigningKey());
        assertEquals(eMat1.getSigningKey(), eMat3.getSigningKey());
        // Check algorithms. Right now we only support AES and HmacSHA256
        assertEquals("AES", eMat1.getEncryptionKey().getAlgorithm());
        assertEquals("HmacSHA256", eMat1.getSigningKey().getAlgorithm());

        // Ensure we can decrypt all of them without hitting ddb more than the minimum
        final MostRecentProvider prov2 = new MostRecentProvider(store, MATERIAL_NAME, 500);
        final DecryptionMaterials dMat1 = prov2.getDecryptionMaterials(ctx(eMat1));
        methodCalls.clear();
        assertEquals(eMat1.getEncryptionKey(), dMat1.getDecryptionKey());
        assertEquals(eMat1.getSigningKey(), dMat1.getVerificationKey());
        final DecryptionMaterials dMat2 = prov2.getDecryptionMaterials(ctx(eMat2));
        assertEquals(eMat2.getEncryptionKey(), dMat2.getDecryptionKey());
        assertEquals(eMat2.getSigningKey(), dMat2.getVerificationKey());
        final DecryptionMaterials dMat3 = prov2.getDecryptionMaterials(ctx(eMat3));
        assertEquals(eMat3.getEncryptionKey(), dMat3.getDecryptionKey());
        assertEquals(eMat3.getSigningKey(), dMat3.getVerificationKey());
        assertTrue("Expected no calls but was " + methodCalls.toString(), methodCalls.isEmpty());
    }

    @Test
    public void singleVersionWithRefresh() throws InterruptedException {
        final MostRecentProvider prov = new MostRecentProvider(store, MATERIAL_NAME, 500);
        assertNull(methodCalls.get("putItem"));
        final EncryptionMaterials eMat1 = prov.getEncryptionMaterials(ctx);
        // It's a new provider, so we see a single putItem
        assertEquals(1, (int) methodCalls.getOrDefault("putItem", 0));
        methodCalls.clear();
        // Ensure the cache is working
        final EncryptionMaterials eMat2 = prov.getEncryptionMaterials(ctx);
        assertTrue(methodCalls.isEmpty());
        assertEquals(0, store.getVersionFromMaterialDescription(eMat1.getMaterialDescription()));
        assertEquals(0, store.getVersionFromMaterialDescription(eMat2.getMaterialDescription()));
        prov.refresh();
        final EncryptionMaterials eMat3 = prov.getEncryptionMaterials(ctx);
        assertEquals(1, (int) methodCalls.getOrDefault("query", 0)); // To find current version
        assertEquals(1, (int) methodCalls.getOrDefault("getItem", 0));
        assertEquals(0, store.getVersionFromMaterialDescription(eMat3.getMaterialDescription()));
        prov.refresh();

        assertEquals(eMat1.getSigningKey(), eMat2.getSigningKey());
        assertEquals(eMat1.getSigningKey(), eMat3.getSigningKey());

        // Ensure that after cache refresh  we only get one more hit as opposed to multiple
        prov.getEncryptionMaterials(ctx);
        Thread.sleep(700);
        // Force refresh
        prov.getEncryptionMaterials(ctx);
        methodCalls.clear();
        // Check to ensure no more hits
        assertEquals(eMat1.getSigningKey(), prov.getEncryptionMaterials(ctx).getSigningKey());
        assertEquals(eMat1.getSigningKey(), prov.getEncryptionMaterials(ctx).getSigningKey());
        assertEquals(eMat1.getSigningKey(), prov.getEncryptionMaterials(ctx).getSigningKey());
        assertEquals(eMat1.getSigningKey(), prov.getEncryptionMaterials(ctx).getSigningKey());
        assertEquals(eMat1.getSigningKey(), prov.getEncryptionMaterials(ctx).getSigningKey());
        assertTrue(methodCalls.isEmpty());

        // Ensure we can decrypt all of them without hitting ddb more than the minimum
        final MostRecentProvider prov2 = new MostRecentProvider(store, MATERIAL_NAME, 500);
        final DecryptionMaterials dMat1 = prov2.getDecryptionMaterials(ctx(eMat1));
        methodCalls.clear();
        assertEquals(eMat1.getEncryptionKey(), dMat1.getDecryptionKey());
        assertEquals(eMat1.getSigningKey(), dMat1.getVerificationKey());
        final DecryptionMaterials dMat2 = prov2.getDecryptionMaterials(ctx(eMat2));
        assertEquals(eMat2.getEncryptionKey(), dMat2.getDecryptionKey());
        assertEquals(eMat2.getSigningKey(), dMat2.getVerificationKey());
        final DecryptionMaterials dMat3 = prov2.getDecryptionMaterials(ctx(eMat3));
        assertEquals(eMat3.getEncryptionKey(), dMat3.getDecryptionKey());
        assertEquals(eMat3.getSigningKey(), dMat3.getVerificationKey());
        assertTrue(methodCalls.isEmpty());
    }

    @Test
    public void twoVersions() throws InterruptedException {
        final MostRecentProvider prov = new MostRecentProvider(store, MATERIAL_NAME, 500);
        assertNull(methodCalls.get("putItem"));
        final EncryptionMaterials eMat1 = prov.getEncryptionMaterials(ctx);
        // It's a new provider, so we see a single putItem
        assertEquals(1, (int) methodCalls.getOrDefault("putItem", 0));
        methodCalls.clear();
        // Create the new material
        store.newProvider(MATERIAL_NAME);
        methodCalls.clear();

        // Ensure the cache is working
        final EncryptionMaterials eMat2 = prov.getEncryptionMaterials(ctx);
        assertTrue(methodCalls.isEmpty());
        assertEquals(0, store.getVersionFromMaterialDescription(eMat1.getMaterialDescription()));
        assertEquals(0, store.getVersionFromMaterialDescription(eMat2.getMaterialDescription()));
        assertTrue(methodCalls.isEmpty());
        // Let the TTL be exceeded
        Thread.sleep(500);
        final EncryptionMaterials eMat3 = prov.getEncryptionMaterials(ctx);

        assertEquals(1, (int) methodCalls.getOrDefault("query", 0)); // To find current version
        assertEquals(1, (int) methodCalls.getOrDefault("getItem", 0)); // To retrieve current version
        assertNull(methodCalls.get("putItem")); // No attempt to create a new item
        assertEquals(1, store.getVersionFromMaterialDescription(eMat3.getMaterialDescription()));

        assertEquals(eMat1.getSigningKey(), eMat2.getSigningKey());
        assertFalse(eMat1.getSigningKey().equals(eMat3.getSigningKey()));

        // Ensure we can decrypt all of them without hitting ddb more than the minimum
        final MostRecentProvider prov2 = new MostRecentProvider(store, MATERIAL_NAME, 500);
        final DecryptionMaterials dMat1 = prov2.getDecryptionMaterials(ctx(eMat1));
        methodCalls.clear();
        assertEquals(eMat1.getEncryptionKey(), dMat1.getDecryptionKey());
        assertEquals(eMat1.getSigningKey(), dMat1.getVerificationKey());
        final DecryptionMaterials dMat2 = prov2.getDecryptionMaterials(ctx(eMat2));
        assertEquals(eMat2.getEncryptionKey(), dMat2.getDecryptionKey());
        assertEquals(eMat2.getSigningKey(), dMat2.getVerificationKey());
        final DecryptionMaterials dMat3 = prov2.getDecryptionMaterials(ctx(eMat3));
        assertEquals(eMat3.getEncryptionKey(), dMat3.getDecryptionKey());
        assertEquals(eMat3.getSigningKey(), dMat3.getVerificationKey());
        // Get item will be hit once for the one old key
        assertEquals(1, methodCalls.size());
        assertEquals(1, (int) methodCalls.getOrDefault("getItem", 0));
    }

    @Test
    public void twoVersionsWithRefresh() throws InterruptedException {
        final MostRecentProvider prov = new MostRecentProvider(store, MATERIAL_NAME, 100);
        assertNull(methodCalls.get("putItem"));
        final EncryptionMaterials eMat1 = prov.getEncryptionMaterials(ctx);
        // It's a new provider, so we see a single putItem
        assertEquals(1, (int) methodCalls.getOrDefault("putItem", 0));
        methodCalls.clear();
        // Create the new material
        store.newProvider(MATERIAL_NAME);
        methodCalls.clear();
        // Ensure the cache is working
        final EncryptionMaterials eMat2 = prov.getEncryptionMaterials(ctx);
        assertTrue(methodCalls.isEmpty());
        assertEquals(0, store.getVersionFromMaterialDescription(eMat1.getMaterialDescription()));
        assertEquals(0, store.getVersionFromMaterialDescription(eMat2.getMaterialDescription()));
        prov.refresh();
        final EncryptionMaterials eMat3 = prov.getEncryptionMaterials(ctx);
        assertEquals(1, (int) methodCalls.getOrDefault("query", 0)); // To find current version
        assertEquals(1, (int) methodCalls.getOrDefault("getItem", 0));
        assertEquals(1, store.getVersionFromMaterialDescription(eMat3.getMaterialDescription()));

        assertEquals(eMat1.getSigningKey(), eMat2.getSigningKey());
        assertFalse(eMat1.getSigningKey().equals(eMat3.getSigningKey()));

        // Ensure we can decrypt all of them without hitting ddb more than the minimum
        final MostRecentProvider prov2 = new MostRecentProvider(store, MATERIAL_NAME, 500);
        final DecryptionMaterials dMat1 = prov2.getDecryptionMaterials(ctx(eMat1));
        methodCalls.clear();
        assertEquals(eMat1.getEncryptionKey(), dMat1.getDecryptionKey());
        assertEquals(eMat1.getSigningKey(), dMat1.getVerificationKey());
        final DecryptionMaterials dMat2 = prov2.getDecryptionMaterials(ctx(eMat2));
        assertEquals(eMat2.getEncryptionKey(), dMat2.getDecryptionKey());
        assertEquals(eMat2.getSigningKey(), dMat2.getVerificationKey());
        final DecryptionMaterials dMat3 = prov2.getDecryptionMaterials(ctx(eMat3));
        assertEquals(eMat3.getEncryptionKey(), dMat3.getDecryptionKey());
        assertEquals(eMat3.getSigningKey(), dMat3.getVerificationKey());
        // Get item will be hit once for the one old key
        assertEquals(1, methodCalls.size());
        assertEquals(1, (int) methodCalls.getOrDefault("getItem", 0));
    }

    @Test
    public void singleVersionTwoMaterials() throws InterruptedException {
        final Map<String, AttributeValue> attr1 = Collections.singletonMap(MATERIAL_PARAM, new AttributeValue("material1"));
        final EncryptionContext ctx1 = ctx(attr1);
        final Map<String, AttributeValue> attr2 = Collections.singletonMap(MATERIAL_PARAM, new AttributeValue("material2"));
        final EncryptionContext ctx2 = ctx(attr2);

        final MostRecentProvider prov = new ExtendedProvider(store, 500);
        assertNull(methodCalls.get("putItem"));
        final EncryptionMaterials eMat1_1 = prov.getEncryptionMaterials(ctx1);
        // It's a new provider, so we see a single putItem
        assertEquals(1, (int) methodCalls.getOrDefault("putItem", 0));
        methodCalls.clear();
        final EncryptionMaterials eMat1_2 = prov.getEncryptionMaterials(ctx2);
        // It's a new provider, so we see a single putItem
        assertEquals(1, (int) methodCalls.getOrDefault("putItem", 0));
        methodCalls.clear();
        // Ensure the two materials are, in fact, different
        assertFalse(eMat1_1.getSigningKey().equals(eMat1_2.getSigningKey()));

        // Ensure the cache is working
        final EncryptionMaterials eMat2_1 = prov.getEncryptionMaterials(ctx1);
        assertTrue(methodCalls.isEmpty());
        assertEquals(0, store.getVersionFromMaterialDescription(eMat1_1.getMaterialDescription()));
        assertEquals(0, store.getVersionFromMaterialDescription(eMat2_1.getMaterialDescription()));
        final EncryptionMaterials eMat2_2 = prov.getEncryptionMaterials(ctx2);
        assertTrue(methodCalls.isEmpty());
        assertEquals(0, store.getVersionFromMaterialDescription(eMat1_2.getMaterialDescription()));
        assertEquals(0, store.getVersionFromMaterialDescription(eMat2_2.getMaterialDescription()));

        // Let the TTL be exceeded
        Thread.sleep(500);
        final EncryptionMaterials eMat3_1 = prov.getEncryptionMaterials(ctx1);
        assertEquals(1, methodCalls.size());
        assertEquals(1, (int) methodCalls.get("query")); // To find current version
        assertEquals(0, store.getVersionFromMaterialDescription(eMat3_1.getMaterialDescription()));
        methodCalls.clear();
        final EncryptionMaterials eMat3_2 = prov.getEncryptionMaterials(ctx2);
        assertEquals(1, methodCalls.size());
        assertEquals(1, (int) methodCalls.get("query")); // To find current version
        assertEquals(0, store.getVersionFromMaterialDescription(eMat3_2.getMaterialDescription()));

        assertEquals(eMat1_1.getSigningKey(), eMat2_1.getSigningKey());
        assertEquals(eMat1_2.getSigningKey(), eMat2_2.getSigningKey());
        assertEquals(eMat1_1.getSigningKey(), eMat3_1.getSigningKey());
        assertEquals(eMat1_2.getSigningKey(), eMat3_2.getSigningKey());
        // Check algorithms. Right now we only support AES and HmacSHA256
        assertEquals("AES", eMat1_1.getEncryptionKey().getAlgorithm());
        assertEquals("AES", eMat1_2.getEncryptionKey().getAlgorithm());
        assertEquals("HmacSHA256", eMat1_1.getSigningKey().getAlgorithm());
        assertEquals("HmacSHA256", eMat1_2.getSigningKey().getAlgorithm());

        // Ensure we can decrypt all of them without hitting ddb more than the minimum
        final MostRecentProvider prov2 = new ExtendedProvider(store, 500);
        final DecryptionMaterials dMat1_1 = prov2.getDecryptionMaterials(ctx(eMat1_1, attr1));
        final DecryptionMaterials dMat1_2 = prov2.getDecryptionMaterials(ctx(eMat1_2, attr2));
        methodCalls.clear();
        assertEquals(eMat1_1.getEncryptionKey(), dMat1_1.getDecryptionKey());
        assertEquals(eMat1_2.getEncryptionKey(), dMat1_2.getDecryptionKey());
        assertEquals(eMat1_1.getSigningKey(), dMat1_1.getVerificationKey());
        assertEquals(eMat1_2.getSigningKey(), dMat1_2.getVerificationKey());
        final DecryptionMaterials dMat2_1 = prov2.getDecryptionMaterials(ctx(eMat2_1, attr1));
        final DecryptionMaterials dMat2_2 = prov2.getDecryptionMaterials(ctx(eMat2_2, attr2));
        assertEquals(eMat2_1.getEncryptionKey(), dMat2_1.getDecryptionKey());
        assertEquals(eMat2_2.getEncryptionKey(), dMat2_2.getDecryptionKey());
        assertEquals(eMat2_1.getSigningKey(), dMat2_1.getVerificationKey());
        assertEquals(eMat2_2.getSigningKey(), dMat2_2.getVerificationKey());
        final DecryptionMaterials dMat3_1 = prov2.getDecryptionMaterials(ctx(eMat3_1, attr1));
        final DecryptionMaterials dMat3_2 = prov2.getDecryptionMaterials(ctx(eMat3_2, attr2));
        assertEquals(eMat3_1.getEncryptionKey(), dMat3_1.getDecryptionKey());
        assertEquals(eMat3_2.getEncryptionKey(), dMat3_2.getDecryptionKey());
        assertEquals(eMat3_1.getSigningKey(), dMat3_1.getVerificationKey());
        assertEquals(eMat3_2.getSigningKey(), dMat3_2.getVerificationKey());
        assertTrue("Expected no calls but was " + methodCalls.toString(), methodCalls.isEmpty());
    }

    @Test
    public void singleVersionWithTwoMaterialsWithRefresh() throws InterruptedException {
        final Map<String, AttributeValue> attr1 = Collections.singletonMap(MATERIAL_PARAM, new AttributeValue("material1"));
        final EncryptionContext ctx1 = ctx(attr1);
        final Map<String, AttributeValue> attr2 = Collections.singletonMap(MATERIAL_PARAM, new AttributeValue("material2"));
        final EncryptionContext ctx2 = ctx(attr2);

        final MostRecentProvider prov = new ExtendedProvider(store, 500);
        assertNull(methodCalls.get("putItem"));
        final EncryptionMaterials eMat1_1 = prov.getEncryptionMaterials(ctx1);
        // It's a new provider, so we see a single putItem
        assertEquals(1, (int) methodCalls.getOrDefault("putItem", 0));
        methodCalls.clear();
        final EncryptionMaterials eMat1_2 = prov.getEncryptionMaterials(ctx2);
        // It's a new provider, so we see a single putItem
        assertEquals(1, (int) methodCalls.getOrDefault("putItem", 0));
        methodCalls.clear();
        // Ensure the two materials are, in fact, different
        assertFalse(eMat1_1.getSigningKey().equals(eMat1_2.getSigningKey()));

        // Ensure the cache is working
        final EncryptionMaterials eMat2_1 = prov.getEncryptionMaterials(ctx1);
        assertTrue(methodCalls.isEmpty());
        assertEquals(0, store.getVersionFromMaterialDescription(eMat1_1.getMaterialDescription()));
        assertEquals(0, store.getVersionFromMaterialDescription(eMat2_1.getMaterialDescription()));
        final EncryptionMaterials eMat2_2 = prov.getEncryptionMaterials(ctx2);
        assertTrue(methodCalls.isEmpty());
        assertEquals(0, store.getVersionFromMaterialDescription(eMat1_2.getMaterialDescription()));
        assertEquals(0, store.getVersionFromMaterialDescription(eMat2_2.getMaterialDescription()));

        prov.refresh();
        final EncryptionMaterials eMat3_1 = prov.getEncryptionMaterials(ctx1);
        assertEquals(1, (int) methodCalls.getOrDefault("query", 0)); // To find current version
        assertEquals(1, (int) methodCalls.getOrDefault("getItem", 0));
        final EncryptionMaterials eMat3_2 = prov.getEncryptionMaterials(ctx2);
        assertEquals(2, (int) methodCalls.getOrDefault("query", 0)); // To find current version
        assertEquals(2, (int) methodCalls.getOrDefault("getItem", 0));
        assertEquals(0, store.getVersionFromMaterialDescription(eMat3_1.getMaterialDescription()));
        assertEquals(0, store.getVersionFromMaterialDescription(eMat3_2.getMaterialDescription()));
        prov.refresh();

        assertEquals(eMat1_1.getSigningKey(), eMat2_1.getSigningKey());
        assertEquals(eMat1_1.getSigningKey(), eMat3_1.getSigningKey());
        assertEquals(eMat1_2.getSigningKey(), eMat2_2.getSigningKey());
        assertEquals(eMat1_2.getSigningKey(), eMat3_2.getSigningKey());

        // Ensure that after cache refresh  we only get one more hit as opposed to multiple
        prov.getEncryptionMaterials(ctx1);
        prov.getEncryptionMaterials(ctx2);
        Thread.sleep(700);
        // Force refresh
        prov.getEncryptionMaterials(ctx1);
        prov.getEncryptionMaterials(ctx2);
        methodCalls.clear();
        // Check to ensure no more hits
        assertEquals(eMat1_1.getSigningKey(), prov.getEncryptionMaterials(ctx1).getSigningKey());
        assertEquals(eMat1_1.getSigningKey(), prov.getEncryptionMaterials(ctx1).getSigningKey());
        assertEquals(eMat1_1.getSigningKey(), prov.getEncryptionMaterials(ctx1).getSigningKey());
        assertEquals(eMat1_1.getSigningKey(), prov.getEncryptionMaterials(ctx1).getSigningKey());
        assertEquals(eMat1_1.getSigningKey(), prov.getEncryptionMaterials(ctx1).getSigningKey());

        assertEquals(eMat1_2.getSigningKey(), prov.getEncryptionMaterials(ctx2).getSigningKey());
        assertEquals(eMat1_2.getSigningKey(), prov.getEncryptionMaterials(ctx2).getSigningKey());
        assertEquals(eMat1_2.getSigningKey(), prov.getEncryptionMaterials(ctx2).getSigningKey());
        assertEquals(eMat1_2.getSigningKey(), prov.getEncryptionMaterials(ctx2).getSigningKey());
        assertEquals(eMat1_2.getSigningKey(), prov.getEncryptionMaterials(ctx2).getSigningKey());
        assertTrue(methodCalls.isEmpty());

        // Ensure we can decrypt all of them without hitting ddb more than the minimum
        final MostRecentProvider prov2 = new ExtendedProvider(store, 500);
        final DecryptionMaterials dMat1_1 = prov2.getDecryptionMaterials(ctx(eMat1_1, attr1));
        final DecryptionMaterials dMat1_2 = prov2.getDecryptionMaterials(ctx(eMat1_2, attr2));
        methodCalls.clear();
        assertEquals(eMat1_1.getEncryptionKey(), dMat1_1.getDecryptionKey());
        assertEquals(eMat1_2.getEncryptionKey(), dMat1_2.getDecryptionKey());
        assertEquals(eMat1_1.getSigningKey(), dMat1_1.getVerificationKey());
        assertEquals(eMat1_2.getSigningKey(), dMat1_2.getVerificationKey());
        final DecryptionMaterials dMat2_1 = prov2.getDecryptionMaterials(ctx(eMat2_1, attr1));
        final DecryptionMaterials dMat2_2 = prov2.getDecryptionMaterials(ctx(eMat2_2, attr2));
        assertEquals(eMat2_1.getEncryptionKey(), dMat2_1.getDecryptionKey());
        assertEquals(eMat2_2.getEncryptionKey(), dMat2_2.getDecryptionKey());
        assertEquals(eMat2_1.getSigningKey(), dMat2_1.getVerificationKey());
        assertEquals(eMat2_2.getSigningKey(), dMat2_2.getVerificationKey());
        final DecryptionMaterials dMat3_1 = prov2.getDecryptionMaterials(ctx(eMat3_1, attr1));
        final DecryptionMaterials dMat3_2 = prov2.getDecryptionMaterials(ctx(eMat3_2, attr2));
        assertEquals(eMat3_1.getEncryptionKey(), dMat3_1.getDecryptionKey());
        assertEquals(eMat3_2.getEncryptionKey(), dMat3_2.getDecryptionKey());
        assertEquals(eMat3_1.getSigningKey(), dMat3_1.getVerificationKey());
        assertEquals(eMat3_2.getSigningKey(), dMat3_2.getVerificationKey());
        assertTrue(methodCalls.isEmpty());
    }

    @Test
    public void twoVersionsWithTwoMaterialsWithRefresh() throws InterruptedException {
        final Map<String, AttributeValue> attr1 = Collections.singletonMap(MATERIAL_PARAM, new AttributeValue("material1"));
        final EncryptionContext ctx1 = ctx(attr1);
        final Map<String, AttributeValue> attr2 = Collections.singletonMap(MATERIAL_PARAM, new AttributeValue("material2"));
        final EncryptionContext ctx2 = ctx(attr2);

        final MostRecentProvider prov = new ExtendedProvider(store, 500);
        assertNull(methodCalls.get("putItem"));
        final EncryptionMaterials eMat1_1 = prov.getEncryptionMaterials(ctx1);
        // It's a new provider, so we see a single putItem
        assertEquals(1, (int) methodCalls.getOrDefault("putItem", 0));
        methodCalls.clear();
        final EncryptionMaterials eMat1_2 = prov.getEncryptionMaterials(ctx2);
        // It's a new provider, so we see a single putItem
        assertEquals(1, (int) methodCalls.getOrDefault("putItem", 0));
        methodCalls.clear();
        // Create the new material
        store.newProvider("material1");
        store.newProvider("material2");
        methodCalls.clear();
        // Ensure the cache is working
        final EncryptionMaterials eMat2_1 = prov.getEncryptionMaterials(ctx1);
        final EncryptionMaterials eMat2_2 = prov.getEncryptionMaterials(ctx2);
        assertTrue(methodCalls.isEmpty());
        assertEquals(0, store.getVersionFromMaterialDescription(eMat1_1.getMaterialDescription()));
        assertEquals(0, store.getVersionFromMaterialDescription(eMat2_1.getMaterialDescription()));
        assertEquals(0, store.getVersionFromMaterialDescription(eMat1_2.getMaterialDescription()));
        assertEquals(0, store.getVersionFromMaterialDescription(eMat2_2.getMaterialDescription()));
        prov.refresh();
        final EncryptionMaterials eMat3_1 = prov.getEncryptionMaterials(ctx1);
        final EncryptionMaterials eMat3_2 = prov.getEncryptionMaterials(ctx2);
        assertEquals(2, (int) methodCalls.getOrDefault("query", 0)); // To find current version
        assertEquals(2, (int) methodCalls.getOrDefault("getItem", 0));
        assertEquals(1, store.getVersionFromMaterialDescription(eMat3_1.getMaterialDescription()));
        assertEquals(1, store.getVersionFromMaterialDescription(eMat3_2.getMaterialDescription()));

        assertEquals(eMat1_1.getSigningKey(), eMat2_1.getSigningKey());
        assertFalse(eMat1_1.getSigningKey().equals(eMat3_1.getSigningKey()));
        assertEquals(eMat1_2.getSigningKey(), eMat2_2.getSigningKey());
        assertFalse(eMat1_2.getSigningKey().equals(eMat3_2.getSigningKey()));

        // Ensure we can decrypt all of them without hitting ddb more than the minimum
        final MostRecentProvider prov2 = new ExtendedProvider(store, 500);
        final DecryptionMaterials dMat1_1 = prov2.getDecryptionMaterials(ctx(eMat1_1, attr1));
        final DecryptionMaterials dMat1_2 = prov2.getDecryptionMaterials(ctx(eMat1_2, attr2));
        methodCalls.clear();
        assertEquals(eMat1_1.getEncryptionKey(), dMat1_1.getDecryptionKey());
        assertEquals(eMat1_2.getEncryptionKey(), dMat1_2.getDecryptionKey());
        assertEquals(eMat1_1.getSigningKey(), dMat1_1.getVerificationKey());
        assertEquals(eMat1_2.getSigningKey(), dMat1_2.getVerificationKey());
        final DecryptionMaterials dMat2_1 = prov2.getDecryptionMaterials(ctx(eMat2_1, attr1));
        final DecryptionMaterials dMat2_2 = prov2.getDecryptionMaterials(ctx(eMat2_2, attr2));
        assertEquals(eMat2_1.getEncryptionKey(), dMat2_1.getDecryptionKey());
        assertEquals(eMat2_2.getEncryptionKey(), dMat2_2.getDecryptionKey());
        assertEquals(eMat2_1.getSigningKey(), dMat2_1.getVerificationKey());
        assertEquals(eMat2_2.getSigningKey(), dMat2_2.getVerificationKey());
        final DecryptionMaterials dMat3_1 = prov2.getDecryptionMaterials(ctx(eMat3_1, attr1));
        final DecryptionMaterials dMat3_2 = prov2.getDecryptionMaterials(ctx(eMat3_2, attr2));
        assertEquals(eMat3_1.getEncryptionKey(), dMat3_1.getDecryptionKey());
        assertEquals(eMat3_2.getEncryptionKey(), dMat3_2.getDecryptionKey());
        assertEquals(eMat3_1.getSigningKey(), dMat3_1.getVerificationKey());
        assertEquals(eMat3_2.getSigningKey(), dMat3_2.getVerificationKey());
        // Get item will be hit once for the one old key
        assertEquals(1, methodCalls.size());
        assertEquals(2, (int) methodCalls.getOrDefault("getItem", 0));
    }

    private static EncryptionContext ctx(final Map<String, AttributeValue> attr) {
        return new EncryptionContext.Builder()
                .withAttributeValues(attr).build();
    }

    private static EncryptionContext ctx(final EncryptionMaterials mat, Map<String, AttributeValue> attr) {
        return new EncryptionContext.Builder()
                .withAttributeValues(attr)
                .withMaterialDescription(mat.getMaterialDescription()).build();
    }

    private static EncryptionContext ctx(final EncryptionMaterials mat) {
        return new EncryptionContext.Builder()
                .withMaterialDescription(mat.getMaterialDescription()).build();
    }

    private static class ExtendedProvider extends MostRecentProvider {
        public ExtendedProvider(ProviderStore keystore, long ttlInMillis) {
            super(keystore, null, ttlInMillis);
        }

        @Override
        public long getCurrentVersion() {
            throw new UnsupportedOperationException();
        }

        @Override
        protected String getMaterialName(final EncryptionContext context) {
            return context.getAttributeValues().get(MATERIAL_PARAM).getS();
        }
    }

    @SuppressWarnings("unchecked")
    private static <T> T instrument(final T obj, final Class<T> clazz, final Map<String, Integer> map) {
        return (T) Proxy.newProxyInstance(clazz.getClassLoader(), new Class[]{clazz},
                new InvocationHandler() {
                    private final Object lock = new Object();

                    @Override
                    public Object invoke(final Object proxy, final Method method, final Object[] args) throws Throwable {
                        synchronized (lock) {
                            try {
                                final Integer oldCount = map.get(method.getName());
                                if (oldCount != null) {
                                    map.put(method.getName(), oldCount + 1);
                                } else {
                                    map.put(method.getName(), 1);
                                }
                                return method.invoke(obj, args);
                            } catch (final InvocationTargetException ex) {
                                throw ex.getCause();
                            }
                        }
                    }
                }
        );
    }
}
