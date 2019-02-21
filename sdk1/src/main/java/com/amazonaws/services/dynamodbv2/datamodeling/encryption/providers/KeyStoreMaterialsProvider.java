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

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStore.Entry;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.KeyStore.ProtectionParameter;
import java.security.KeyStore.SecretKeyEntry;
import java.security.KeyStore.TrustedCertificateEntry;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableEntryException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

import com.amazonaws.services.dynamodbv2.datamodeling.DynamoDBMappingException;
import com.amazonaws.services.dynamodbv2.datamodeling.encryption.EncryptionContext;
import com.amazonaws.services.dynamodbv2.datamodeling.encryption.materials.AsymmetricRawMaterials;
import com.amazonaws.services.dynamodbv2.datamodeling.encryption.materials.DecryptionMaterials;
import com.amazonaws.services.dynamodbv2.datamodeling.encryption.materials.EncryptionMaterials;
import com.amazonaws.services.dynamodbv2.datamodeling.encryption.materials.SymmetricRawMaterials;

/**
 * @author Greg Rubin 
 */
public class KeyStoreMaterialsProvider implements EncryptionMaterialsProvider {
    private final Map<String, String> description;
    private final String encryptionAlias;
    private final String signingAlias;
    private final ProtectionParameter encryptionProtection;
    private final ProtectionParameter signingProtection;
    private final KeyStore keyStore;
    private final AtomicReference<CurrentMaterials> currMaterials =
            new AtomicReference<KeyStoreMaterialsProvider.CurrentMaterials>();

    public KeyStoreMaterialsProvider(KeyStore keyStore, String encryptionAlias, String signingAlias, Map<String, String> description)
            throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableEntryException {
        this(keyStore, encryptionAlias, signingAlias, null, null, description);
    }

    public KeyStoreMaterialsProvider(KeyStore keyStore, String encryptionAlias, String signingAlias,
            ProtectionParameter encryptionProtection, ProtectionParameter signingProtection,
            Map<String, String> description)
            throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableEntryException {
        super();
        this.keyStore = keyStore;
        this.encryptionAlias = encryptionAlias;
        this.signingAlias = signingAlias;
        this.encryptionProtection = encryptionProtection;
        this.signingProtection = signingProtection;
        this.description = Collections.unmodifiableMap(new HashMap<String, String>(description));

        validateKeys();
        loadKeys();
    }

    @Override
    public DecryptionMaterials getDecryptionMaterials(EncryptionContext context) {
        CurrentMaterials materials = currMaterials.get();
        if (context.getMaterialDescription().entrySet().containsAll(description.entrySet())) {
            if (materials.encryptionEntry instanceof SecretKeyEntry) {
                return materials.symRawMaterials;
            } else {
                try {
                    return makeAsymMaterials(materials, context.getMaterialDescription());
                } catch (GeneralSecurityException ex) {
                    throw new DynamoDBMappingException("Unable to decrypt envelope key", ex);
                }
            }
        } else {
            return null;
        }
    }

    @Override
    public EncryptionMaterials getEncryptionMaterials(EncryptionContext context) {
        CurrentMaterials materials = currMaterials.get();
        if (materials.encryptionEntry instanceof SecretKeyEntry) {
            return materials.symRawMaterials;
        } else {
            try {
                return makeAsymMaterials(materials, description);
            } catch (GeneralSecurityException ex) {
                throw new DynamoDBMappingException("Unable to encrypt envelope key", ex);
            }
        }
    }
    
    private AsymmetricRawMaterials makeAsymMaterials(CurrentMaterials materials,
            Map<String, String> description) throws GeneralSecurityException {
        KeyPair encryptionPair = entry2Pair(materials.encryptionEntry);
        if (materials.signingEntry instanceof SecretKeyEntry) {
            return new AsymmetricRawMaterials(encryptionPair,
                    ((SecretKeyEntry) materials.signingEntry).getSecretKey(), description);
        } else {
            return new AsymmetricRawMaterials(encryptionPair, entry2Pair(materials.signingEntry),
                    description);
        }
    }

    private static KeyPair entry2Pair(Entry entry) {
        PublicKey pub = null;
        PrivateKey priv = null;

        if (entry instanceof PrivateKeyEntry) {
            PrivateKeyEntry pk = (PrivateKeyEntry) entry;
            if (pk.getCertificate() != null) {
                pub = pk.getCertificate().getPublicKey();
            }
            priv = pk.getPrivateKey();
        } else if (entry instanceof TrustedCertificateEntry) {
            TrustedCertificateEntry tc = (TrustedCertificateEntry) entry;
            pub = tc.getTrustedCertificate().getPublicKey();
        } else {
            throw new IllegalArgumentException(
                    "Only entry types PrivateKeyEntry and TrustedCertificateEntry are supported.");
        }
        return new KeyPair(pub, priv);
    }

    /**
     * Reloads the keys from the underlying keystore by calling
     * {@link KeyStore#getEntry(String, ProtectionParameter)} again for each of them.
     */
    @Override
    public void refresh() {
        try {
            loadKeys();
        } catch (GeneralSecurityException ex) {
            throw new DynamoDBMappingException("Unable to load keys from keystore", ex);
        }
    }

    private void validateKeys() throws KeyStoreException {
        if (!keyStore.containsAlias(encryptionAlias)) {
            throw new IllegalArgumentException("Keystore does not contain alias: "
                    + encryptionAlias);
        }
        if (!keyStore.containsAlias(signingAlias)) {
            throw new IllegalArgumentException("Keystore does not contain alias: "
                    + signingAlias);
        }
    }

    private void loadKeys() throws NoSuchAlgorithmException, UnrecoverableEntryException,
            KeyStoreException {
        Entry encryptionEntry = keyStore.getEntry(encryptionAlias, encryptionProtection);
        Entry signingEntry = keyStore.getEntry(signingAlias, signingProtection);
        CurrentMaterials newMaterials = new CurrentMaterials(encryptionEntry, signingEntry);
        currMaterials.set(newMaterials);
    }

    private class CurrentMaterials {
        public final Entry encryptionEntry;
        public final Entry signingEntry;
        public final SymmetricRawMaterials symRawMaterials;

        public CurrentMaterials(Entry encryptionEntry, Entry signingEntry) {
            super();
            this.encryptionEntry = encryptionEntry;
            this.signingEntry = signingEntry;

            if (encryptionEntry instanceof SecretKeyEntry) {
                if (signingEntry instanceof SecretKeyEntry) {
                    this.symRawMaterials = new SymmetricRawMaterials(
                            ((SecretKeyEntry) encryptionEntry).getSecretKey(),
                            ((SecretKeyEntry) signingEntry).getSecretKey(),
                            description);
                } else {
                    this.symRawMaterials = new SymmetricRawMaterials(
                            ((SecretKeyEntry) encryptionEntry).getSecretKey(),
                            entry2Pair(signingEntry),
                            description);
                }
            } else {
                this.symRawMaterials = null;
            }
        }
    }
}
