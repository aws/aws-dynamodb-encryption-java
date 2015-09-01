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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.junit.Before;
import org.junit.Test;

import com.amazonaws.services.dynamodb.mock.AmazonDynamoDBMock;
import com.amazonaws.services.dynamodbv2.AmazonDynamoDB;
import com.amazonaws.services.dynamodbv2.datamodeling.encryption.DynamoDBEncryptor;
import com.amazonaws.services.dynamodbv2.datamodeling.encryption.EncryptionContext;
import com.amazonaws.services.dynamodbv2.datamodeling.encryption.materials.DecryptionMaterials;
import com.amazonaws.services.dynamodbv2.datamodeling.encryption.materials.EncryptionMaterials;
import com.amazonaws.services.dynamodbv2.datamodeling.encryption.providers.EncryptionMaterialsProvider;
import com.amazonaws.services.dynamodbv2.datamodeling.encryption.providers.MostRecentProvider;
import com.amazonaws.services.dynamodbv2.datamodeling.encryption.providers.SymmetricStaticProvider;
import com.amazonaws.services.dynamodbv2.datamodeling.encryption.providers.store.MetaStore;
import com.amazonaws.services.dynamodbv2.datamodeling.encryption.providers.store.ProviderStore;
import com.amazonaws.services.dynamodbv2.model.ProvisionedThroughput;

public class MostRecentProviderTests {
    private static final String TABLE_NAME = "keystoreTable";
    private static final String MATERIAL_NAME = "material";
    private static final SecretKey AES_KEY = new SecretKeySpec(new byte[] { 0,
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 }, "AES");
    private static final SecretKey HMAC_KEY = new SecretKeySpec(new byte[] { 0,
            1, 2, 3, 4, 5, 6, 7 }, "HmacSHA256");
    private static final EncryptionMaterialsProvider BASE_PROVIDER = new SymmetricStaticProvider(AES_KEY, HMAC_KEY);
    private static final DynamoDBEncryptor ENCRYPTOR = DynamoDBEncryptor.getInstance(BASE_PROVIDER);

    private AmazonDynamoDB client;
    private Map<String, Integer> methodCalls;
    private ProviderStore store;
    private EncryptionContext ctx;

    @Before
    public void setup() {
        methodCalls = new HashMap<String, Integer>();
        client = instrument(new AmazonDynamoDBMock(), AmazonDynamoDB.class, methodCalls);
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
    public void singleMaterial() throws InterruptedException {
        final MostRecentProvider prov = new MostRecentProvider(store, MATERIAL_NAME, 500);
        assertNull(methodCalls.get("putItem"));
        final EncryptionMaterials eMat1 = prov.getEncryptionMaterials(ctx);
        // It's a new provider, so we see a single putItem
        assertEquals(1, (int) methodCalls.get("putItem"));
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
        assertEquals(1, (int) methodCalls.get("query")); // To find current version
        assertEquals(0, store.getVersionFromMaterialDescription(eMat3.getMaterialDescription()));

        assertEquals(eMat1.getSigningKey(), eMat2.getSigningKey());
        assertEquals(eMat1.getSigningKey(), eMat3.getSigningKey());

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
    public void singleMaterialWithRefresh() throws InterruptedException {
        final MostRecentProvider prov = new MostRecentProvider(store, MATERIAL_NAME, 100);
        assertNull(methodCalls.get("putItem"));
        final EncryptionMaterials eMat1 = prov.getEncryptionMaterials(ctx);
        // It's a new provider, so we see a single putItem
        assertEquals(1, (int) methodCalls.get("putItem"));
        methodCalls.clear();
        // Ensure the cache is working
        final EncryptionMaterials eMat2 = prov.getEncryptionMaterials(ctx);
        assertTrue(methodCalls.isEmpty());
        assertEquals(0, store.getVersionFromMaterialDescription(eMat1.getMaterialDescription()));
        assertEquals(0, store.getVersionFromMaterialDescription(eMat2.getMaterialDescription()));
        prov.refresh();
        final EncryptionMaterials eMat3 = prov.getEncryptionMaterials(ctx);
        assertEquals(1, (int) methodCalls.get("query")); // To find current version
        assertEquals(1, (int) methodCalls.get("getItem"));
        assertEquals(0, store.getVersionFromMaterialDescription(eMat3.getMaterialDescription()));

        assertEquals(eMat1.getSigningKey(), eMat2.getSigningKey());
        assertEquals(eMat1.getSigningKey(), eMat3.getSigningKey());

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
    public void twoMaterials() throws InterruptedException {
        final MostRecentProvider prov = new MostRecentProvider(store, MATERIAL_NAME, 500);
        assertNull(methodCalls.get("putItem"));
        final EncryptionMaterials eMat1 = prov.getEncryptionMaterials(ctx);
        // It's a new provider, so we see a single putItem
        assertEquals(1, (int) methodCalls.get("putItem"));
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

        assertEquals(1, (int) methodCalls.get("query")); // To find current version
        assertEquals(1, (int) methodCalls.get("getItem")); // To retrieve current version
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
        assertEquals(1, (int) methodCalls.get("getItem"));
    }

    @Test
    public void twoMaterialsWithRefresh() throws InterruptedException {
        final MostRecentProvider prov = new MostRecentProvider(store, MATERIAL_NAME, 100);
        assertNull(methodCalls.get("putItem"));
        final EncryptionMaterials eMat1 = prov.getEncryptionMaterials(ctx);
        // It's a new provider, so we see a single putItem
        assertEquals(1, (int) methodCalls.get("putItem"));
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
        assertEquals(1, (int) methodCalls.get("query")); // To find current version
        assertEquals(1, (int) methodCalls.get("getItem"));
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
        assertEquals(1, (int) methodCalls.get("getItem"));
    }

    private static EncryptionContext ctx(final EncryptionMaterials mat) {
        return new EncryptionContext.Builder()
        .withMaterialDescription(mat.getMaterialDescription()).build();
    }

    @SuppressWarnings("unchecked")
    private static <T> T instrument(final T obj, final Class<T> clazz, final Map<String, Integer> map) {
        return (T) Proxy.newProxyInstance(clazz.getClassLoader(), new Class[] { clazz },
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
