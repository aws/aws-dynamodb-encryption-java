/*
 * Copyright 2015-2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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
package software.amazon.cryptools.dynamodbencryptionclientsdk2.encryption.providers;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.testng.AssertJUnit.assertEquals;
import static org.testng.AssertJUnit.assertFalse;

import java.util.Collections;
import java.util.Map;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.mockito.Mockito;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import software.amazon.cryptools.dynamodbencryptionclientsdk2.encryption.DynamoDbEncryptor;
import software.amazon.cryptools.dynamodbencryptionclientsdk2.encryption.EncryptionContext;
import software.amazon.cryptools.dynamodbencryptionclientsdk2.encryption.materials.DecryptionMaterials;
import software.amazon.cryptools.dynamodbencryptionclientsdk2.encryption.materials.EncryptionMaterials;
import software.amazon.cryptools.dynamodbencryptionclientsdk2.encryption.providers.store.MetaStore;
import software.amazon.cryptools.dynamodbencryptionclientsdk2.encryption.providers.store.ProviderStore;
import software.amazon.cryptools.dynamodbencryptionclientsdk2.testing.AttributeValueBuilder;
import software.amazon.cryptools.dynamodbencryptionclientsdk2.testing.LocalDynamoDb;

import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.awssdk.services.dynamodb.model.GetItemRequest;
import software.amazon.awssdk.services.dynamodb.model.ProvisionedThroughput;
import software.amazon.awssdk.services.dynamodb.model.PutItemRequest;
import software.amazon.awssdk.services.dynamodb.model.QueryRequest;

public class MostRecentProviderTests {
    private static final String TABLE_NAME = "keystoreTable";
    private static final String MATERIAL_NAME = "material";
    private static final String MATERIAL_PARAM = "materialName";
    private static final SecretKey AES_KEY = new SecretKeySpec(new byte[] { 0,
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 }, "AES");
    private static final SecretKey HMAC_KEY = new SecretKeySpec(new byte[] { 0,
            1, 2, 3, 4, 5, 6, 7 }, "HmacSHA256");
    private static final EncryptionMaterialsProvider BASE_PROVIDER = new SymmetricStaticProvider(AES_KEY, HMAC_KEY);
    private static final DynamoDbEncryptor ENCRYPTOR =
        DynamoDbEncryptor.builder().encryptionMaterialsProvider(BASE_PROVIDER).build();

    private LocalDynamoDb localDynamoDb = new LocalDynamoDb();
    private DynamoDbClient client;
    private ProviderStore store;
    private EncryptionContext ctx;

    @BeforeMethod
    public void setup() {
        localDynamoDb.start();
        client = Mockito.spy(localDynamoDb.createLimitedWrappedClient());
        MetaStore.createTable(client, TABLE_NAME, ProvisionedThroughput.builder()
                                                                       .writeCapacityUnits(1L)
                                                                       .readCapacityUnits(1L)
                                                                       .build());
        store = new MetaStore(client, TABLE_NAME, ENCRYPTOR);
        ctx = EncryptionContext.builder().build();
        reset(client);
    }

    @AfterMethod
    public void stopLocalDynamoDb() {
        localDynamoDb.stop();
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
        verify(client, never()).putItem(any(PutItemRequest.class));
        final EncryptionMaterials eMat1 = prov.getEncryptionMaterials(ctx);
        // It's a new provider, so we see a single putItem
        verify(client).putItem(any(PutItemRequest.class));
        reset(client);
        // Ensure the cache is working
        final EncryptionMaterials eMat2 = prov.getEncryptionMaterials(ctx);
        verifyNoMoreInteractions(client);
        assertEquals(0, store.getVersionFromMaterialDescription(eMat1.getMaterialDescription()));
        assertEquals(0, store.getVersionFromMaterialDescription(eMat2.getMaterialDescription()));
        // Let the TTL be exceeded
        Thread.sleep(500);
        final EncryptionMaterials eMat3 = prov.getEncryptionMaterials(ctx);
        verify(client).query(any(QueryRequest.class));
        verifyNoMoreInteractions(client);
        assertEquals(0, store.getVersionFromMaterialDescription(eMat3.getMaterialDescription()));

        assertEquals(eMat1.getSigningKey(), eMat2.getSigningKey());
        assertEquals(eMat1.getSigningKey(), eMat3.getSigningKey());
        // Check algorithms. Right now we only support AES and HmacSHA256
        assertEquals("AES", eMat1.getEncryptionKey().getAlgorithm());
        assertEquals("HmacSHA256", eMat1.getSigningKey().getAlgorithm());

        // Ensure we can decrypt all of them without hitting ddb more than the minimum
        final MostRecentProvider prov2 = new MostRecentProvider(store, MATERIAL_NAME, 500);
        final DecryptionMaterials dMat1 = prov2.getDecryptionMaterials(ctx(eMat1));
        reset(client);
        assertEquals(eMat1.getEncryptionKey(), dMat1.getDecryptionKey());
        assertEquals(eMat1.getSigningKey(), dMat1.getVerificationKey());
        final DecryptionMaterials dMat2 = prov2.getDecryptionMaterials(ctx(eMat2));
        assertEquals(eMat2.getEncryptionKey(), dMat2.getDecryptionKey());
        assertEquals(eMat2.getSigningKey(), dMat2.getVerificationKey());
        final DecryptionMaterials dMat3 = prov2.getDecryptionMaterials(ctx(eMat3));
        assertEquals(eMat3.getEncryptionKey(), dMat3.getDecryptionKey());
        assertEquals(eMat3.getSigningKey(), dMat3.getVerificationKey());
        verifyNoMoreInteractions(client);
    }
    
    @Test
    public void singleVersionWithRefresh() throws InterruptedException {
        final MostRecentProvider prov = new MostRecentProvider(store, MATERIAL_NAME, 500);
        verify(client, never()).putItem(any(PutItemRequest.class));
        final EncryptionMaterials eMat1 = prov.getEncryptionMaterials(ctx);
        // It's a new provider, so we see a single putItem
        verify(client).putItem(any(PutItemRequest.class));
        reset(client);
        // Ensure the cache is working
        final EncryptionMaterials eMat2 = prov.getEncryptionMaterials(ctx);
        verifyNoMoreInteractions(client);
        assertEquals(0, store.getVersionFromMaterialDescription(eMat1.getMaterialDescription()));
        assertEquals(0, store.getVersionFromMaterialDescription(eMat2.getMaterialDescription()));
        prov.refresh();
        final EncryptionMaterials eMat3 = prov.getEncryptionMaterials(ctx);
        verify(client).query(any(QueryRequest.class)); // To find current version
        verify(client).getItem(any(GetItemRequest.class));
        assertEquals(0, store.getVersionFromMaterialDescription(eMat3.getMaterialDescription()));
        prov.refresh();

        assertEquals(eMat1.getSigningKey(), eMat2.getSigningKey());
        assertEquals(eMat1.getSigningKey(), eMat3.getSigningKey());

        // Ensure that after cache refresh  we only get one more hit as opposed to multiple
        prov.getEncryptionMaterials(ctx);
        Thread.sleep(700);
        // Force refresh
        prov.getEncryptionMaterials(ctx);
        reset(client);
        // Check to ensure no more hits
        assertEquals(eMat1.getSigningKey(), prov.getEncryptionMaterials(ctx).getSigningKey());
        assertEquals(eMat1.getSigningKey(), prov.getEncryptionMaterials(ctx).getSigningKey());
        assertEquals(eMat1.getSigningKey(), prov.getEncryptionMaterials(ctx).getSigningKey());
        assertEquals(eMat1.getSigningKey(), prov.getEncryptionMaterials(ctx).getSigningKey());
        assertEquals(eMat1.getSigningKey(), prov.getEncryptionMaterials(ctx).getSigningKey());
        verifyNoMoreInteractions(client);

        // Ensure we can decrypt all of them without hitting ddb more than the minimum
        final MostRecentProvider prov2 = new MostRecentProvider(store, MATERIAL_NAME, 500);
        final DecryptionMaterials dMat1 = prov2.getDecryptionMaterials(ctx(eMat1));
        reset(client);
        assertEquals(eMat1.getEncryptionKey(), dMat1.getDecryptionKey());
        assertEquals(eMat1.getSigningKey(), dMat1.getVerificationKey());
        final DecryptionMaterials dMat2 = prov2.getDecryptionMaterials(ctx(eMat2));
        assertEquals(eMat2.getEncryptionKey(), dMat2.getDecryptionKey());
        assertEquals(eMat2.getSigningKey(), dMat2.getVerificationKey());
        final DecryptionMaterials dMat3 = prov2.getDecryptionMaterials(ctx(eMat3));
        assertEquals(eMat3.getEncryptionKey(), dMat3.getDecryptionKey());
        assertEquals(eMat3.getSigningKey(), dMat3.getVerificationKey());
        verifyNoMoreInteractions(client);
    }

    
    @Test
    public void twoVersions() throws InterruptedException {
        final MostRecentProvider prov = new MostRecentProvider(store, MATERIAL_NAME, 500);
        verify(client, never()).putItem(any(PutItemRequest.class));
        final EncryptionMaterials eMat1 = prov.getEncryptionMaterials(ctx);
        // It's a new provider, so we see a single putItem
        verify(client).putItem(any(PutItemRequest.class));
        reset(client);
        // Create the new material
        store.newProvider(MATERIAL_NAME);
        reset(client);

        // Ensure the cache is working
        final EncryptionMaterials eMat2 = prov.getEncryptionMaterials(ctx);
        verifyNoMoreInteractions(client);
        assertEquals(0, store.getVersionFromMaterialDescription(eMat1.getMaterialDescription()));
        assertEquals(0, store.getVersionFromMaterialDescription(eMat2.getMaterialDescription()));
        verifyNoMoreInteractions(client);
        // Let the TTL be exceeded
        Thread.sleep(500);
        final EncryptionMaterials eMat3 = prov.getEncryptionMaterials(ctx);

        verify(client).query(any(QueryRequest.class)); // To find current version
        verify(client).getItem(any(GetItemRequest.class)); // To retrieve current version
        verify(client, never()).putItem(any(PutItemRequest.class)); // No attempt to create a new item
        assertEquals(1, store.getVersionFromMaterialDescription(eMat3.getMaterialDescription()));

        assertEquals(eMat1.getSigningKey(), eMat2.getSigningKey());
        assertFalse(eMat1.getSigningKey().equals(eMat3.getSigningKey()));

        // Ensure we can decrypt all of them without hitting ddb more than the minimum
        final MostRecentProvider prov2 = new MostRecentProvider(store, MATERIAL_NAME, 500);
        final DecryptionMaterials dMat1 = prov2.getDecryptionMaterials(ctx(eMat1));
        reset(client);
        assertEquals(eMat1.getEncryptionKey(), dMat1.getDecryptionKey());
        assertEquals(eMat1.getSigningKey(), dMat1.getVerificationKey());
        final DecryptionMaterials dMat2 = prov2.getDecryptionMaterials(ctx(eMat2));
        assertEquals(eMat2.getEncryptionKey(), dMat2.getDecryptionKey());
        assertEquals(eMat2.getSigningKey(), dMat2.getVerificationKey());
        final DecryptionMaterials dMat3 = prov2.getDecryptionMaterials(ctx(eMat3));
        assertEquals(eMat3.getEncryptionKey(), dMat3.getDecryptionKey());
        assertEquals(eMat3.getSigningKey(), dMat3.getVerificationKey());
        // Get item will be hit once for the one old key
        verify(client).getItem(any(GetItemRequest.class));
        verifyNoMoreInteractions(client);
    }

    @Test
    public void twoVersionsWithRefresh() throws InterruptedException {
        final MostRecentProvider prov = new MostRecentProvider(store, MATERIAL_NAME, 100);
        verify(client, never()).putItem(any(PutItemRequest.class));
        final EncryptionMaterials eMat1 = prov.getEncryptionMaterials(ctx);
        // It's a new provider, so we see a single putItem
        verify(client).putItem(any(PutItemRequest.class));
        reset(client);
        // Create the new material
        store.newProvider(MATERIAL_NAME);
        reset(client);
        // Ensure the cache is working
        final EncryptionMaterials eMat2 = prov.getEncryptionMaterials(ctx);
        verifyNoMoreInteractions(client);
        assertEquals(0, store.getVersionFromMaterialDescription(eMat1.getMaterialDescription()));
        assertEquals(0, store.getVersionFromMaterialDescription(eMat2.getMaterialDescription()));
        prov.refresh();
        final EncryptionMaterials eMat3 = prov.getEncryptionMaterials(ctx);
        verify(client).query(any(QueryRequest.class)); // To find current version
        verify(client).getItem(any(GetItemRequest.class));
        assertEquals(1, store.getVersionFromMaterialDescription(eMat3.getMaterialDescription()));

        assertEquals(eMat1.getSigningKey(), eMat2.getSigningKey());
        assertFalse(eMat1.getSigningKey().equals(eMat3.getSigningKey()));

        // Ensure we can decrypt all of them without hitting ddb more than the minimum
        final MostRecentProvider prov2 = new MostRecentProvider(store, MATERIAL_NAME, 500);
        final DecryptionMaterials dMat1 = prov2.getDecryptionMaterials(ctx(eMat1));
        reset(client);
        assertEquals(eMat1.getEncryptionKey(), dMat1.getDecryptionKey());
        assertEquals(eMat1.getSigningKey(), dMat1.getVerificationKey());
        final DecryptionMaterials dMat2 = prov2.getDecryptionMaterials(ctx(eMat2));
        assertEquals(eMat2.getEncryptionKey(), dMat2.getDecryptionKey());
        assertEquals(eMat2.getSigningKey(), dMat2.getVerificationKey());
        final DecryptionMaterials dMat3 = prov2.getDecryptionMaterials(ctx(eMat3));
        assertEquals(eMat3.getEncryptionKey(), dMat3.getDecryptionKey());
        assertEquals(eMat3.getSigningKey(), dMat3.getVerificationKey());
        // Get item will be hit once for the one old key
        verify(client).getItem(any(GetItemRequest.class));
        verifyNoMoreInteractions(client);
    }

    @Test
    public void singleVersionTwoMaterials() throws InterruptedException {
        final Map<String, AttributeValue> attr1 = Collections.singletonMap(MATERIAL_PARAM, AttributeValueBuilder.ofS("material1"));
        final EncryptionContext ctx1 = ctx(attr1);
        final Map<String, AttributeValue> attr2 = Collections.singletonMap(MATERIAL_PARAM, AttributeValueBuilder.ofS("material2"));
        final EncryptionContext ctx2 = ctx(attr2);

        final MostRecentProvider prov = new ExtendedProvider(store, 500);
        verify(client, never()).putItem(any(PutItemRequest.class));
        final EncryptionMaterials eMat1_1 = prov.getEncryptionMaterials(ctx1);
        // It's a new provider, so we see a single putItem
        verify(client).putItem(any(PutItemRequest.class));
        reset(client);
        final EncryptionMaterials eMat1_2 = prov.getEncryptionMaterials(ctx2);
        // It's a new provider, so we see a single putItem
        verify(client).putItem(any(PutItemRequest.class));
        reset(client);
        // Ensure the two materials are, in fact, different
        assertFalse(eMat1_1.getSigningKey().equals(eMat1_2.getSigningKey()));

        // Ensure the cache is working
        final EncryptionMaterials eMat2_1 = prov.getEncryptionMaterials(ctx1);
        verifyNoMoreInteractions(client);
        assertEquals(0, store.getVersionFromMaterialDescription(eMat1_1.getMaterialDescription()));
        assertEquals(0, store.getVersionFromMaterialDescription(eMat2_1.getMaterialDescription()));
        final EncryptionMaterials eMat2_2 = prov.getEncryptionMaterials(ctx2);
        verifyNoMoreInteractions(client);
        assertEquals(0, store.getVersionFromMaterialDescription(eMat1_2.getMaterialDescription()));
        assertEquals(0, store.getVersionFromMaterialDescription(eMat2_2.getMaterialDescription()));

        // Let the TTL be exceeded
        Thread.sleep(500);
        final EncryptionMaterials eMat3_1 = prov.getEncryptionMaterials(ctx1);
        verify(client).query(any(QueryRequest.class)); // To find current version
        verifyNoMoreInteractions(client);
        assertEquals(0, store.getVersionFromMaterialDescription(eMat3_1.getMaterialDescription()));
        reset(client);
        final EncryptionMaterials eMat3_2 = prov.getEncryptionMaterials(ctx2);
        verify(client).query(any(QueryRequest.class)); // To find current version
        verifyNoMoreInteractions(client);
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
        reset(client);
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
        verifyNoMoreInteractions(client);
    }

    @Test
    public void singleVersionWithTwoMaterialsWithRefresh() throws InterruptedException {
        final Map<String, AttributeValue> attr1 = Collections.singletonMap(MATERIAL_PARAM, AttributeValueBuilder.ofS("material1"));
        final EncryptionContext ctx1 = ctx(attr1);
        final Map<String, AttributeValue> attr2 = Collections.singletonMap(MATERIAL_PARAM, AttributeValueBuilder.ofS("material2"));
        final EncryptionContext ctx2 = ctx(attr2);

        final MostRecentProvider prov = new ExtendedProvider(store, 500);
        verify(client, never()).putItem(any(PutItemRequest.class));
        final EncryptionMaterials eMat1_1 = prov.getEncryptionMaterials(ctx1);
        // It's a new provider, so we see a single putItem
        verify(client).putItem(any(PutItemRequest.class));
        reset(client);
        final EncryptionMaterials eMat1_2 = prov.getEncryptionMaterials(ctx2);
        // It's a new provider, so we see a single putItem
        verify(client).putItem(any(PutItemRequest.class));
        reset(client);
        // Ensure the two materials are, in fact, different
        assertFalse(eMat1_1.getSigningKey().equals(eMat1_2.getSigningKey()));

        // Ensure the cache is working
        final EncryptionMaterials eMat2_1 = prov.getEncryptionMaterials(ctx1);
        verifyNoMoreInteractions(client);
        assertEquals(0, store.getVersionFromMaterialDescription(eMat1_1.getMaterialDescription()));
        assertEquals(0, store.getVersionFromMaterialDescription(eMat2_1.getMaterialDescription()));
        final EncryptionMaterials eMat2_2 = prov.getEncryptionMaterials(ctx2);
        verifyNoMoreInteractions(client);
        assertEquals(0, store.getVersionFromMaterialDescription(eMat1_2.getMaterialDescription()));
        assertEquals(0, store.getVersionFromMaterialDescription(eMat2_2.getMaterialDescription()));

        prov.refresh();
        final EncryptionMaterials eMat3_1 = prov.getEncryptionMaterials(ctx1);
        verify(client).query(any(QueryRequest.class)); // To find current version
        verify(client).getItem(any(GetItemRequest.class));
        final EncryptionMaterials eMat3_2 = prov.getEncryptionMaterials(ctx2);
        verify(client, times(2)).query(any(QueryRequest.class)); // To find current version
        verify(client, times(2)).getItem(any(GetItemRequest.class));
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
        reset(client);
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
        verifyNoMoreInteractions(client);

        // Ensure we can decrypt all of them without hitting ddb more than the minimum
        final MostRecentProvider prov2 = new ExtendedProvider(store, 500);
        final DecryptionMaterials dMat1_1 = prov2.getDecryptionMaterials(ctx(eMat1_1, attr1));
        final DecryptionMaterials dMat1_2 = prov2.getDecryptionMaterials(ctx(eMat1_2, attr2));
        reset(client);
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
        verifyNoMoreInteractions(client);
    }

    @Test
    public void twoVersionsWithTwoMaterialsWithRefresh() {
        final Map<String, AttributeValue> attr1 = Collections.singletonMap(MATERIAL_PARAM, AttributeValueBuilder.ofS("material1"));
        final EncryptionContext ctx1 = ctx(attr1);
        final Map<String, AttributeValue> attr2 = Collections.singletonMap(MATERIAL_PARAM, AttributeValueBuilder.ofS("material2"));
        final EncryptionContext ctx2 = ctx(attr2);

        final MostRecentProvider prov = new ExtendedProvider(store, 500);
        verify(client, never()).putItem(any(PutItemRequest.class));
        final EncryptionMaterials eMat1_1 = prov.getEncryptionMaterials(ctx1);
        // It's a new provider, so we see a single putItem
        verify(client).putItem(any(PutItemRequest.class));
        reset(client);
        final EncryptionMaterials eMat1_2 = prov.getEncryptionMaterials(ctx2);
        // It's a new provider, so we see a single putItem
        verify(client).putItem(any(PutItemRequest.class));
        reset(client);
        // Create the new material
        store.newProvider("material1");
        store.newProvider("material2");
        reset(client);
        // Ensure the cache is working
        final EncryptionMaterials eMat2_1 = prov.getEncryptionMaterials(ctx1);
        final EncryptionMaterials eMat2_2 = prov.getEncryptionMaterials(ctx2);
        verifyNoMoreInteractions(client);
        assertEquals(0, store.getVersionFromMaterialDescription(eMat1_1.getMaterialDescription()));
        assertEquals(0, store.getVersionFromMaterialDescription(eMat2_1.getMaterialDescription()));
        assertEquals(0, store.getVersionFromMaterialDescription(eMat1_2.getMaterialDescription()));
        assertEquals(0, store.getVersionFromMaterialDescription(eMat2_2.getMaterialDescription()));
        prov.refresh();
        final EncryptionMaterials eMat3_1 = prov.getEncryptionMaterials(ctx1);
        final EncryptionMaterials eMat3_2 = prov.getEncryptionMaterials(ctx2);
        verify(client, times(2)).query(any(QueryRequest.class)); // To find current version
        verify(client, times(2)).getItem(any(GetItemRequest.class));
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
        reset(client);
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
        verify(client, times(2)).getItem(any(GetItemRequest.class));
        verifyNoMoreInteractions(client);
    }

    private static EncryptionContext ctx(final Map<String, AttributeValue> attr) {
        return EncryptionContext.builder()
            .attributeValues(attr).build();
    }

    private static EncryptionContext ctx(final EncryptionMaterials mat, Map<String, AttributeValue> attr) {
        return EncryptionContext.builder()
            .attributeValues(attr)
            .materialDescription(mat.getMaterialDescription()).build();
    }

    private static EncryptionContext ctx(final EncryptionMaterials mat) {
        return EncryptionContext.builder()
            .materialDescription(mat.getMaterialDescription()).build();
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
            return context.getAttributeValues().get(MATERIAL_PARAM).s();
        }
    }
}
