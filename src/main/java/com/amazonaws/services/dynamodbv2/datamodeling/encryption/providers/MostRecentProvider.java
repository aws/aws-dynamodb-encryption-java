/*
 * Copyright 2016 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.locks.ReentrantLock;

import com.amazonaws.services.dynamodbv2.datamodeling.encryption.EncryptionContext;
import com.amazonaws.services.dynamodbv2.datamodeling.encryption.materials.DecryptionMaterials;
import com.amazonaws.services.dynamodbv2.datamodeling.encryption.materials.EncryptionMaterials;
import com.amazonaws.services.dynamodbv2.datamodeling.encryption.providers.store.ProviderStore;
import com.amazonaws.services.dynamodbv2.datamodeling.internal.LRUCache;

/**
 * This meta-Provider encrypts data with the most recent version of keying materials from a
 * {@link ProviderStore} and decrypts using whichever version is appropriate. It also caches the
 * results from the {@link ProviderStore} to avoid excessive load on the backing systems. The cache
 * is not currently configurable.
 */
public class MostRecentProvider implements EncryptionMaterialsProvider {
    private static final long MILLI_TO_NANO = 1000000L;
    private static final long TTL_GRACE_IN_NANO = 500 * MILLI_TO_NANO;
    private final ProviderStore keystore;
    protected final String defaultMaterialName;
    private final long ttlInNanos;
    private final LRUCache<EncryptionMaterialsProvider> cache;
    private final LRUCache<LockedState> currentVersions;

    /**
     * Creates a new {@link MostRecentProvider}.
     * 
     * @param ttlInMillis
     *            The length of time in milliseconds to cache the most recent provider
     */
    public MostRecentProvider(final ProviderStore keystore, final String materialName, final long ttlInMillis) {
        this.keystore = checkNotNull(keystore, "keystore must not be null");
        this.defaultMaterialName = materialName;
        this.ttlInNanos = ttlInMillis * MILLI_TO_NANO;
        this.cache = new LRUCache<EncryptionMaterialsProvider>(1000);
        this.currentVersions = new LRUCache<>(1000);
    }

    @Override
    public EncryptionMaterials getEncryptionMaterials(EncryptionContext context) {
        final String materialName = getMaterialName(context);
        final LockedState ls = getCurrentVersion(materialName);

        final State s = ls.getState();
        if (s.provider != null && System.nanoTime() - s.lastUpdated <= ttlInNanos) {
            return s.provider.getEncryptionMaterials(context);
        }
        if (s.provider == null || System.nanoTime() - s.lastUpdated > ttlInNanos + TTL_GRACE_IN_NANO) {
            // Either we don't have a provider at all, or we're more than 500 milliseconds past
            // our update time. Either way, grab the lock and force an update.
            ls.lock();
        } else if (!ls.tryLock()) {
            // If we can't get the lock immediately, just use the current provider
            return s.provider.getEncryptionMaterials(context);
        }

        try {
            final long newVersion = keystore.getMaxVersion(materialName);
            final long currentVersion;
            final EncryptionMaterialsProvider currentProvider;
            if (newVersion < 0) {
                // First version of the material, so we want to allow creation
                currentVersion = 0;
                currentProvider = keystore.getOrCreate(materialName, currentVersion);
                cache.add(buildCacheKey(materialName, currentVersion), currentProvider);
            } else if (newVersion != s.currentVersion) {
                // We're retrieving an existing version, so we avoid the creation
                // flow as it is slower
                currentVersion = newVersion;
                currentProvider = keystore.getProvider(materialName, currentVersion);
                cache.add(buildCacheKey(materialName, currentVersion), currentProvider);
            } else {
                // Our version hasn't changed, so we'll just re-use the existing
                // provider to avoid the overhead of retrieving and building a new one
                currentVersion = newVersion;
                currentProvider = s.provider;
                // There is no need to add this to the cache as it's already there
            }

            ls.update(currentProvider, currentVersion);

            return ls.getState().provider.getEncryptionMaterials(context);
        } finally {
            ls.unlock();
        }
    }

    public DecryptionMaterials getDecryptionMaterials(EncryptionContext context) {
        final String materialName = getMaterialName(context);
        final long version = keystore.getVersionFromMaterialDescription(
                context.getMaterialDescription());
        EncryptionMaterialsProvider provider = cache.get(buildCacheKey(materialName, version));
        if (provider == null) {
            provider = keystore.getProvider(materialName, version);
            cache.add(buildCacheKey(materialName, version), provider);
        }
        return provider.getDecryptionMaterials(context);
    }

    /**
     * Completely empties the cache of both the current and old versions.
     */
    @Override
    public void refresh() {
        currentVersions.clear();
        cache.clear();
    }

    public String getMaterialName() {
        return defaultMaterialName;
    }

    public long getTtlInMills() {
        return ttlInNanos / MILLI_TO_NANO;
    }

    /**
     * The current version of the materials being used for encryption. Returns -1 if we do not
     * currently have a current version.
     */
    public long getCurrentVersion() {
        return getCurrentVersion(getMaterialName()).getState().currentVersion;
    }

    /**
     * The last time the current version was updated. Returns 0 if we do not currently have a
     * current version.
     */
    public long getLastUpdated() {
        return getCurrentVersion(getMaterialName()).getState().lastUpdated / MILLI_TO_NANO;
    }

    protected String getMaterialName(final EncryptionContext context) {
        return defaultMaterialName;
    }

    private LockedState getCurrentVersion(final String materialName) {
        final LockedState result = currentVersions.get(materialName);
        if (result == null) {
            currentVersions.add(materialName, new LockedState());
            return currentVersions.get(materialName);
        } else {
            return result;
        }
    }

    private static String buildCacheKey(final String materialName, final long version) {
        StringBuilder result = new StringBuilder(materialName);
        result.append('#');
        result.append(version);
        return result.toString();
    }

    private static <V> V checkNotNull(final V ref, final String errMsg) {
        if (ref == null) {
            throw new NullPointerException(errMsg);
        } else {
            return ref;
        }
    }

    private static class LockedState {
        private final ReentrantLock lock = new ReentrantLock(true);
        private volatile AtomicReference<State> state = new AtomicReference<>(new State());

        public State getState() {
            return state.get();
        }

        public void unlock() {
            lock.unlock();
        }

        public boolean tryLock() {
            return lock.tryLock();
        }

        public void lock() {
            lock.lock();
        }

        public void update(EncryptionMaterialsProvider provider, long currentVersion) {
            if (!lock.isHeldByCurrentThread()) {
                throw new IllegalStateException("Lock not held by current thread");
            }
            state.set(new State(provider, currentVersion));
        }
    }

    private static class State {
        public final EncryptionMaterialsProvider provider;
        public final long currentVersion;
        public final long lastUpdated;

        public State() {
            this(null, -1);
        }

        public State(EncryptionMaterialsProvider provider, long currentVersion) {
            this.provider = provider;
            this.currentVersion = currentVersion;
            this.lastUpdated = currentVersion == -1 ? 0 : System.nanoTime();
        }
    }
}
