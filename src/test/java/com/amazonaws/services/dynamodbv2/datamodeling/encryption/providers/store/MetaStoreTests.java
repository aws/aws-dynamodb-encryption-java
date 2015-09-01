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
package com.amazonaws.services.dynamodbv2.datamodeling.encryption.providers.store;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.junit.Before;
import org.junit.Test;

import com.amazonaws.services.dynamodb.mock.AmazonDynamoDBMock;
import com.amazonaws.services.dynamodbv2.AmazonDynamoDB;
import com.amazonaws.services.dynamodbv2.datamodeling.DynamoDBMappingException;
import com.amazonaws.services.dynamodbv2.datamodeling.encryption.DynamoDBEncryptor;
import com.amazonaws.services.dynamodbv2.datamodeling.encryption.EncryptionContext;
import com.amazonaws.services.dynamodbv2.datamodeling.encryption.materials.DecryptionMaterials;
import com.amazonaws.services.dynamodbv2.datamodeling.encryption.materials.EncryptionMaterials;
import com.amazonaws.services.dynamodbv2.datamodeling.encryption.providers.EncryptionMaterialsProvider;
import com.amazonaws.services.dynamodbv2.datamodeling.encryption.providers.SymmetricStaticProvider;
import com.amazonaws.services.dynamodbv2.datamodeling.encryption.providers.store.MetaStore;
import com.amazonaws.services.dynamodbv2.datamodeling.encryption.providers.store.ProviderStore;
import com.amazonaws.services.dynamodbv2.model.ProvisionedThroughput;

public class MetaStoreTests {
    private static final String TABLE_NAME = "keystoreTable";
    private static final String MATERIAL_NAME = "material";
    private static final SecretKey AES_KEY = new SecretKeySpec(new byte[] { 0,
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 }, "AES");
    private static final SecretKey HMAC_KEY = new SecretKeySpec(new byte[] { 0,
            1, 2, 3, 4, 5, 6, 7 }, "HmacSHA256");
    private static final EncryptionMaterialsProvider BASE_PROVIDER = new SymmetricStaticProvider(AES_KEY, HMAC_KEY);
    private static final DynamoDBEncryptor ENCRYPTOR = DynamoDBEncryptor.getInstance(BASE_PROVIDER);

    private AmazonDynamoDB client;
    private ProviderStore store;
    private EncryptionContext ctx;

    @Before
    public void setup() {
        client = synchronize(new AmazonDynamoDBMock(), AmazonDynamoDB.class);
        MetaStore.createTable(client, TABLE_NAME, new ProvisionedThroughput(1L, 1L));
        store = new MetaStore(client, TABLE_NAME, ENCRYPTOR);
        ctx = new EncryptionContext.Builder().build();
    }

    @Test
    public void testNoMaterials() {
        assertEquals(-1, store.getMaxVersion(MATERIAL_NAME));
    }

    @Test
    public void singleMaterial() {
        assertEquals(-1, store.getMaxVersion(MATERIAL_NAME));
        final EncryptionMaterialsProvider prov = store.newProvider(MATERIAL_NAME);
        assertEquals(0, store.getMaxVersion(MATERIAL_NAME));

        final EncryptionMaterials eMat = prov.getEncryptionMaterials(ctx);
        final SecretKey encryptionKey = eMat.getEncryptionKey();
        assertNotNull(encryptionKey);

        final DecryptionMaterials dMat = prov.getDecryptionMaterials(ctx(eMat));
        assertEquals(0, store.getVersionFromMaterialDescription(eMat.getMaterialDescription()));
        assertEquals(encryptionKey, dMat.getDecryptionKey());
        assertEquals(eMat.getSigningKey(), dMat.getVerificationKey());
    }

    @Test
    public void singleMaterialExplicitAccess() {
        assertEquals(-1, store.getMaxVersion(MATERIAL_NAME));
        final EncryptionMaterialsProvider prov1 = store.newProvider(MATERIAL_NAME);
        assertEquals(0, store.getMaxVersion(MATERIAL_NAME));
        final EncryptionMaterialsProvider prov2 = store.getProvider(MATERIAL_NAME);

        final EncryptionMaterials eMat = prov1.getEncryptionMaterials(ctx);
        final SecretKey encryptionKey = eMat.getEncryptionKey();
        assertNotNull(encryptionKey);

        final DecryptionMaterials dMat = prov2.getDecryptionMaterials(ctx(eMat));
        assertEquals(0, store.getVersionFromMaterialDescription(eMat.getMaterialDescription()));
        assertEquals(encryptionKey, dMat.getDecryptionKey());
        assertEquals(eMat.getSigningKey(), dMat.getVerificationKey());
    }

    @Test
    public void singleMaterialExplicitAccessWithVersion() {
        assertEquals(-1, store.getMaxVersion(MATERIAL_NAME));
        final EncryptionMaterialsProvider prov1 = store.newProvider(MATERIAL_NAME);
        assertEquals(0, store.getMaxVersion(MATERIAL_NAME));
        final EncryptionMaterialsProvider prov2 = store.getProvider(MATERIAL_NAME, 0);

        final EncryptionMaterials eMat = prov1.getEncryptionMaterials(ctx);
        final SecretKey encryptionKey = eMat.getEncryptionKey();
        assertNotNull(encryptionKey);

        final DecryptionMaterials dMat = prov2.getDecryptionMaterials(ctx(eMat));
        assertEquals(0, store.getVersionFromMaterialDescription(eMat.getMaterialDescription()));
        assertEquals(encryptionKey, dMat.getDecryptionKey());
        assertEquals(eMat.getSigningKey(), dMat.getVerificationKey());
    }

    @Test
    public void singleMaterialWithImplicitCreation() {
        assertEquals(-1, store.getMaxVersion(MATERIAL_NAME));
        final EncryptionMaterialsProvider prov = store.getProvider(MATERIAL_NAME);
        assertEquals(0, store.getMaxVersion(MATERIAL_NAME));

        final EncryptionMaterials eMat = prov.getEncryptionMaterials(ctx);
        final SecretKey encryptionKey = eMat.getEncryptionKey();
        assertNotNull(encryptionKey);

        final DecryptionMaterials dMat = prov.getDecryptionMaterials(ctx(eMat));
        assertEquals(0, store.getVersionFromMaterialDescription(eMat.getMaterialDescription()));
        assertEquals(encryptionKey, dMat.getDecryptionKey());
        assertEquals(eMat.getSigningKey(), dMat.getVerificationKey());
    }

    @Test
    public void twoDifferentMaterials() {
        assertEquals(-1, store.getMaxVersion(MATERIAL_NAME));
        final EncryptionMaterialsProvider prov1 = store.newProvider(MATERIAL_NAME);
        assertEquals(0, store.getMaxVersion(MATERIAL_NAME));
        final EncryptionMaterialsProvider prov2 = store.newProvider(MATERIAL_NAME);
        assertEquals(1, store.getMaxVersion(MATERIAL_NAME));

        final EncryptionMaterials eMat = prov1.getEncryptionMaterials(ctx);
        assertEquals(0, store.getVersionFromMaterialDescription(eMat.getMaterialDescription()));
        final SecretKey encryptionKey = eMat.getEncryptionKey();
        assertNotNull(encryptionKey);

        try {
            prov2.getDecryptionMaterials(ctx(eMat));
            fail("Missing expected exception");
        } catch (final DynamoDBMappingException ex) {
            // Expected Exception
        }
        final EncryptionMaterials eMat2 = prov2.getEncryptionMaterials(ctx);
        assertEquals(1, store.getVersionFromMaterialDescription(eMat2.getMaterialDescription()));
    }

    @Test
    public void getOrCreateCollision() {
        assertEquals(-1, store.getMaxVersion(MATERIAL_NAME));
        final EncryptionMaterialsProvider prov1 = store.getOrCreate(MATERIAL_NAME, 0);
        assertEquals(0, store.getMaxVersion(MATERIAL_NAME));
        final EncryptionMaterialsProvider prov2 = store.getOrCreate(MATERIAL_NAME, 0);

        final EncryptionMaterials eMat = prov1.getEncryptionMaterials(ctx);
        final SecretKey encryptionKey = eMat.getEncryptionKey();
        assertNotNull(encryptionKey);

        final DecryptionMaterials dMat = prov2.getDecryptionMaterials(ctx(eMat));
        assertEquals(encryptionKey, dMat.getDecryptionKey());
        assertEquals(eMat.getSigningKey(), dMat.getVerificationKey());
    }

    @Test
    public void newProviderCollision() throws InterruptedException {
        final SlowNewProvider slowProv = new SlowNewProvider();
        assertEquals(-1, store.getMaxVersion(MATERIAL_NAME));
        assertEquals(-1, slowProv.slowStore.getMaxVersion(MATERIAL_NAME));

        slowProv.start();
        Thread.sleep(100);
        final EncryptionMaterialsProvider prov1 = store.newProvider(MATERIAL_NAME);
        slowProv.join();
        assertEquals(0, store.getMaxVersion(MATERIAL_NAME));
        assertEquals(0, slowProv.slowStore.getMaxVersion(MATERIAL_NAME));
        final EncryptionMaterialsProvider prov2 = slowProv.result;

        final EncryptionMaterials eMat = prov1.getEncryptionMaterials(ctx);
        final SecretKey encryptionKey = eMat.getEncryptionKey();
        assertNotNull(encryptionKey);

        final DecryptionMaterials dMat = prov2.getDecryptionMaterials(ctx(eMat));
        assertEquals(encryptionKey, dMat.getDecryptionKey());
        assertEquals(eMat.getSigningKey(), dMat.getVerificationKey());
    }

    @Test(expected=IndexOutOfBoundsException.class)
    public void invalidVersion() {
        store.getProvider(MATERIAL_NAME, 1000);
    }

    private static EncryptionContext ctx(final EncryptionMaterials mat) {
        return new EncryptionContext.Builder()
        .withMaterialDescription(mat.getMaterialDescription()).build();
    }

    private class SlowNewProvider extends Thread {
        public volatile EncryptionMaterialsProvider result;
        public ProviderStore slowStore = new MetaStore(client, TABLE_NAME, ENCRYPTOR) {
            @Override
            public EncryptionMaterialsProvider newProvider(final String materialName) {
                final long nextId = getMaxVersion(materialName) + 1;
                try {
                    Thread.sleep(1000);
                } catch (final InterruptedException e) {
                    // Ignored
                }
                return getOrCreate(materialName, nextId);
            }
        };

        @Override
        public void run() {
            result = slowStore.newProvider(MATERIAL_NAME);
        }
    }

    @SuppressWarnings("unchecked")
    private static <T> T synchronize(final T obj, final Class<T> clazz) {
        return (T) Proxy.newProxyInstance(clazz.getClassLoader(), new Class[] { clazz },
                new InvocationHandler() {
            private final Object lock = new Object();

            @Override
            public Object invoke(final Object proxy, final Method method, final Object[] args) throws Throwable {
                synchronized (lock) {
                    try {
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
