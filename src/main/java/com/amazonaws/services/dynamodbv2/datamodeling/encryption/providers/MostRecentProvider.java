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

import com.amazonaws.services.dynamodbv2.datamodeling.internal.LRUCache;
import com.amazonaws.services.dynamodbv2.datamodeling.encryption.EncryptionContext;
import com.amazonaws.services.dynamodbv2.datamodeling.encryption.materials.DecryptionMaterials;
import com.amazonaws.services.dynamodbv2.datamodeling.encryption.materials.EncryptionMaterials;
import com.amazonaws.services.dynamodbv2.datamodeling.encryption.providers.store.ProviderStore;

/**
 * This meta-Provider encrypts data with the most recent version of keying materials from a
 * {@link ProviderStore} and decrypts using whichever version is appropriate. It also caches the
 * results from the {@link ProviderStore} to avoid excessive load on the backing systems. The cache
 * is not currently configurable.
 */
public class MostRecentProvider implements EncryptionMaterialsProvider {
    private final Object lock;
    private final ProviderStore keystore;
    private final String materialName;
    private final long ttlInMillis;
    private final LRUCache<EncryptionMaterialsProvider> cache;
    private EncryptionMaterialsProvider currentProvider;
    private long currentVersion;
    private long lastUpdated;

    /**
     * Creates a new {@link MostRecentProvider}.
     * 
     * @param ttlInMillis
     *            The length of time in milliseconds to cache the most recent provider
     */
    public MostRecentProvider(final ProviderStore keystore, final String materialName, final long ttlInMillis) {
        this.keystore = checkNotNull(keystore, "keystore must not be null");
        this.materialName = checkNotNull(materialName, "materialName must not be null");
        this.ttlInMillis = ttlInMillis;
        this.cache = new LRUCache<EncryptionMaterialsProvider>(1000);
        this.lock = new Object();
        currentProvider = null;
        currentVersion = -1;
        lastUpdated = 0;
    }

    @Override
    public EncryptionMaterials getEncryptionMaterials(EncryptionContext context) {
        synchronized (lock) {
            if ((System.currentTimeMillis() - lastUpdated) > ttlInMillis) {
                long newVersion = keystore.getMaxVersion(materialName);
                if (newVersion < 0) {
                    currentVersion = 0;
                    currentProvider = keystore.getOrCreate(materialName, currentVersion);
                } else if (newVersion != currentVersion) {
                    currentVersion = newVersion;
                    currentProvider = keystore.getProvider(materialName, currentVersion);
                    cache.add(Long.toString(currentVersion), currentProvider);
                }
                lastUpdated = System.currentTimeMillis();
            }
            return currentProvider.getEncryptionMaterials(context);
        }
    }

    public DecryptionMaterials getDecryptionMaterials(EncryptionContext context) {
        final long version = keystore.getVersionFromMaterialDescription(
                context.getMaterialDescription());
        EncryptionMaterialsProvider provider = cache.get(Long.toString(version));
        if (provider == null) {
            provider = keystore.getProvider(materialName, version);
            cache.add(Long.toString(version), provider);
        }
        return provider.getDecryptionMaterials(context);
    }

    /**
     * Completely empties the cache of both the current and old versions.
     */
    @Override
    public void refresh() {
        synchronized (lock) {
            lastUpdated = 0;
            currentVersion = -1;
            currentProvider = null;
        }
        cache.clear();
    }

    public String getMaterialName() {
        return materialName;
    }

    public long getTtlInMills() {
        return ttlInMillis;
    }

    /**
     * The current version of the materials being used for encryption. Returns -1 if we do not
     * currently have a current version.
     */
    public long getCurrentVersion() {
        synchronized (lock) {
            return currentVersion;
        }
    }

    /**
     * The last time the current version was updated. Returns 0 if we do not currently have a
     * current version.
     */
    public long getLastUpdated() {
        synchronized (lock) {
            return lastUpdated;
        }
    }

    private static <V> V checkNotNull(final V ref, final String errMsg) {
        if (ref == null) {
            throw new NullPointerException(errMsg);
        } else {
            return ref;
        }
    }
}
