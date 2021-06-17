// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazonaws.services.dynamodbv2.datamodeling.encryption.providers;

import static com.amazonaws.services.dynamodbv2.datamodeling.internal.Utils.checkNotNull;

import com.amazonaws.services.dynamodbv2.datamodeling.encryption.EncryptionContext;
import com.amazonaws.services.dynamodbv2.datamodeling.encryption.materials.DecryptionMaterials;
import com.amazonaws.services.dynamodbv2.datamodeling.encryption.materials.EncryptionMaterials;
import com.amazonaws.services.dynamodbv2.datamodeling.encryption.providers.store.ProviderStore;
import com.amazonaws.services.dynamodbv2.datamodeling.internal.TTLCache;
import com.amazonaws.services.dynamodbv2.datamodeling.internal.TTLCache.EntryLoader;
import java.util.concurrent.TimeUnit;

/**
 * This meta-Provider encrypts data with the most recent version of keying materials from a {@link
 * ProviderStore} and decrypts using whichever version is appropriate. It also caches the results
 * from the {@link ProviderStore} to avoid excessive load on the backing systems.
 */
public class CachingMostRecentProvider implements EncryptionMaterialsProvider {
  private static final long INITIAL_VERSION = 0;
  private static final String PROVIDER_CACHE_KEY_DELIM = "#";
  private static final int DEFAULT_CACHE_MAX_SIZE = 1000;

  private final long ttlInNanos;
  private final ProviderStore keystore;
  protected final String defaultMaterialName;
  private final TTLCache<EncryptionMaterialsProvider> providerCache;
  private final TTLCache<Long> versionCache;

  private final EntryLoader<Long> versionLoader =
      new EntryLoader<Long>() {
        @Override
        public Long load(String entryKey) {
          return keystore.getMaxVersion(entryKey);
        }
      };

  private final EntryLoader<EncryptionMaterialsProvider> providerLoader =
      new EntryLoader<EncryptionMaterialsProvider>() {
        @Override
        public EncryptionMaterialsProvider load(String entryKey) {
          final String[] parts = entryKey.split(PROVIDER_CACHE_KEY_DELIM, 2);
          if (parts.length != 2) {
            throw new IllegalStateException("Invalid cache key for provider cache: " + entryKey);
          }
          return keystore.getProvider(parts[0], Long.parseLong(parts[1]));
        }
      };

  /**
   * Creates a new {@link CachingMostRecentProvider}.
   *
   * @param keystore The key store that this provider will use to determine which material and which
   *     version of material to use
   * @param materialName The name of the materials associated with this provider
   * @param ttlInMillis The length of time in milliseconds to cache the most recent provider
   */
  public CachingMostRecentProvider(
      final ProviderStore keystore, final String materialName, final long ttlInMillis) {
    this(keystore, materialName, ttlInMillis, DEFAULT_CACHE_MAX_SIZE);
  }

  /**
   * Creates a new {@link CachingMostRecentProvider}.
   *
   * @param keystore The key store that this provider will use to determine which material and which
   *     version of material to use
   * @param materialName The name of the materials associated with this provider
   * @param ttlInMillis The length of time in milliseconds to cache the most recent provider
   * @param maxCacheSize The maximum size of the underlying caches this provider uses. Entries will
   *     be evicted from the cache once this size is exceeded.
   */
  public CachingMostRecentProvider(
      final ProviderStore keystore,
      final String materialName,
      final long ttlInMillis,
      final int maxCacheSize) {
    this.keystore = checkNotNull(keystore, "keystore must not be null");
    this.defaultMaterialName = materialName;
    this.ttlInNanos = TimeUnit.MILLISECONDS.toNanos(ttlInMillis);

    this.providerCache = new TTLCache<>(maxCacheSize, ttlInMillis, providerLoader);
    this.versionCache = new TTLCache<>(maxCacheSize, ttlInMillis, versionLoader);
  }

  @Override
  public EncryptionMaterials getEncryptionMaterials(EncryptionContext context) {
    final String materialName = getMaterialName(context);
    final long currentVersion = versionCache.load(materialName);

    if (currentVersion < 0) {
      // The material hasn't been created yet, so specify a loading function
      // to create the first version of materials and update both caches.
      // We want this to be done as part of the cache load to ensure that this logic
      // only happens once in a multithreaded environment,
      // in order to limit calls to the keystore's dependencies.
      final String cacheKey = buildCacheKey(materialName, INITIAL_VERSION);
      EncryptionMaterialsProvider newProvider =
          providerCache.load(
              cacheKey,
              s -> {
                // Create the new material in the keystore
                final String[] parts = s.split(PROVIDER_CACHE_KEY_DELIM, 2);
                if (parts.length != 2) {
                  throw new IllegalStateException("Invalid cache key for provider cache: " + s);
                }
                EncryptionMaterialsProvider provider =
                    keystore.getOrCreate(parts[0], Long.parseLong(parts[1]));

                // We now should have version 0 in our keystore.
                // Update the version cache for this material as a side effect
                versionCache.put(materialName, INITIAL_VERSION);

                // Return the new materials to be put into the cache
                return provider;
              });

      return newProvider.getEncryptionMaterials(context);
    } else {
      final String cacheKey = buildCacheKey(materialName, currentVersion);
      return providerCache.load(cacheKey).getEncryptionMaterials(context);
    }
  }

  public DecryptionMaterials getDecryptionMaterials(EncryptionContext context) {
    final long version =
        keystore.getVersionFromMaterialDescription(context.getMaterialDescription());
    final String materialName = getMaterialName(context);
    final String cacheKey = buildCacheKey(materialName, version);

    EncryptionMaterialsProvider provider = providerCache.load(cacheKey);
    return provider.getDecryptionMaterials(context);
  }

  /** Completely empties the cache of both the current and old versions. */
  @Override
  public void refresh() {
    versionCache.clear();
    providerCache.clear();
  }

  public String getMaterialName() {
    return defaultMaterialName;
  }

  public long getTtlInMills() {
    return TimeUnit.NANOSECONDS.toMillis(ttlInNanos);
  }

  /**
   * The current version of the materials being used for encryption. Returns -1 if we do not
   * currently have a current version.
   */
  public long getCurrentVersion() {
    return versionCache.load(getMaterialName());
  }

  /**
   * The last time the current version was updated. Returns 0 if we do not currently have a current
   * version.
   */
  public long getLastUpdated() {
    // We cache a version of -1 to mean that there is not a current version
    if (versionCache.load(getMaterialName()) < 0) {
      return 0;
    }
    // Otherwise, return the last update time of that entry
    return TimeUnit.NANOSECONDS.toMillis(versionCache.getLastUpdated(getMaterialName()));
  }

  protected String getMaterialName(final EncryptionContext context) {
    return defaultMaterialName;
  }

  private static String buildCacheKey(final String materialName, final long version) {
    StringBuilder result = new StringBuilder(materialName);
    result.append(PROVIDER_CACHE_KEY_DELIM);
    result.append(version);
    return result.toString();
  }
}
