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

import java.util.Map;

import com.amazonaws.services.dynamodbv2.datamodeling.encryption.providers.EncryptionMaterialsProvider;

/**
 * Provides a standard way to retrieve and optionally create {@link EncryptionMaterialsProvider}s
 * backed by some form of persistent storage.
 * 
 * @author rubin
 *
 */
public abstract class ProviderStore {

    /**
     * Returns the most recent provider with the specified name. If there are no providers with this
     * name, it will create one with version 0.
     */
    public EncryptionMaterialsProvider getProvider(final String materialName) {
        final long currVersion = getMaxVersion(materialName);
        if (currVersion >= 0) {
            return getProvider(materialName, currVersion);
        } else {
            return getOrCreate(materialName, 0);
        }
    }

    /**
     * Returns the provider with the specified name and version.
     *
     * @throws IndexOutOfBoundsException
     *             if {@code version} is not a valid version
     */
    public abstract EncryptionMaterialsProvider getProvider(final String materialName, final long version);

    /**
     * Creates a new provider with a version one greater than the current max version. If multiple
     * clients attempt to create a provider with this same version simultaneously, they will
     * properly coordinate and the result will be that a single provider is created and that all
     * ProviderStores return the same one.
     */
    public EncryptionMaterialsProvider newProvider(final String materialName) {
        final long nextId = getMaxVersion(materialName) + 1;
        return getOrCreate(materialName, nextId);
    }

    /**
     * Returns the provider with the specified name and version and creates it if it doesn't exist.
     * 
     * @throws UnsupportedOperationException
     *             if a new provider cannot be created
     */
    public EncryptionMaterialsProvider getOrCreate(final String materialName, final long nextId) {
        try {
            return getProvider(materialName, nextId);
        } catch (final IndexOutOfBoundsException ex) {
            throw new UnsupportedOperationException("This ProviderStore does not support creation.", ex);
        }
    }

    /**
     * Returns the maximum version number associated with {@code materialName}. If there are no
     * versions, returns -1.
     */
    public abstract long getMaxVersion(final String materialName);

    /**
     * Extracts the material version from {@code description}.
     */
    public abstract long getVersionFromMaterialDescription(final Map<String, String> description);
}
