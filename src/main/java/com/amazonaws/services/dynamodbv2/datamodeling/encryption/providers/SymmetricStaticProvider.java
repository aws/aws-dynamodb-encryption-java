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

import java.security.KeyPair;
import java.util.Collections;
import java.util.Map;

import javax.crypto.SecretKey;

import com.amazonaws.services.dynamodbv2.datamodeling.encryption.EncryptionContext;
import com.amazonaws.services.dynamodbv2.datamodeling.encryption.materials.CryptographicMaterials;
import com.amazonaws.services.dynamodbv2.datamodeling.encryption.materials.DecryptionMaterials;
import com.amazonaws.services.dynamodbv2.datamodeling.encryption.materials.EncryptionMaterials;
import com.amazonaws.services.dynamodbv2.datamodeling.encryption.materials.SymmetricRawMaterials;

/**
 * A provider which always returns the same provided symmetric
 * encryption/decryption key and the same signing/verification key(s).
 * 
 * @author Greg Rubin 
 */
public class SymmetricStaticProvider implements EncryptionMaterialsProvider {
    private final SymmetricRawMaterials materials;

    /**
     * @param encryptionKey
     *            the value to be returned by
     *            {@link #getEncryptionMaterials(EncryptionContext)} and
     *            {@link #getDecryptionMaterials(EncryptionContext)}
     * @param signingPair
     *            the keypair used to sign/verify the data stored in Dynamo. If
     *            only the public key is provided, then this provider may be
     *            used for decryption, but not encryption.
     */
    public SymmetricStaticProvider(SecretKey encryptionKey, KeyPair signingPair) {
        this(encryptionKey, signingPair, Collections.<String, String>emptyMap());
    }
    
    /**
     * @param encryptionKey
     *            the value to be returned by
     *            {@link #getEncryptionMaterials(EncryptionContext)} and
     *            {@link #getDecryptionMaterials(EncryptionContext)}
     * @param signingPair
     *            the keypair used to sign/verify the data stored in Dynamo. If
     *            only the public key is provided, then this provider may be
     *            used for decryption, but not encryption.
     * @param description
     *            the value to be returned by
     *            {@link CryptographicMaterials#getMaterialDescription()} for
     *            any {@link CryptographicMaterials} returned by this object.
     */
    public SymmetricStaticProvider(SecretKey encryptionKey,
            KeyPair signingPair, Map<String, String> description) {
        materials = new SymmetricRawMaterials(encryptionKey, signingPair,
                description);
    }

    /**
     * @param encryptionKey
     *            the value to be returned by
     *            {@link #getEncryptionMaterials(EncryptionContext)} and
     *            {@link #getDecryptionMaterials(EncryptionContext)}
     * @param macKey
     *            the key used to sign/verify the data stored in Dynamo.
     */
    public SymmetricStaticProvider(SecretKey encryptionKey, SecretKey macKey) {
        this(encryptionKey, macKey, Collections.<String, String>emptyMap());
    }
    
    /**
     * @param encryptionKey
     *            the value to be returned by
     *            {@link #getEncryptionMaterials(EncryptionContext)} and
     *            {@link #getDecryptionMaterials(EncryptionContext)}
     * @param macKey
     *            the key used to sign/verify the data stored in Dynamo.
     * @param description
     *            the value to be returned by
     *            {@link CryptographicMaterials#getMaterialDescription()} for
     *            any {@link CryptographicMaterials} returned by this object.
     */
    public SymmetricStaticProvider(SecretKey encryptionKey, SecretKey macKey, Map<String, String> description) {
        materials = new SymmetricRawMaterials(encryptionKey, macKey, description);
    }

    /**
     * Returns the <code>encryptionKey</code> provided to the constructor if and only if
     * <code>materialDescription</code> is a super-set (may be equal) to the
     * <code>description</code> provided to the constructor.
     */
    @Override
    public DecryptionMaterials getDecryptionMaterials(EncryptionContext context) {
        if (context.getMaterialDescription().entrySet().containsAll(materials.getMaterialDescription().entrySet())) {
            return materials;
        }
        else {
            return null;
        }
    }

    /**
     * Returns the <code>encryptionKey</code> provided to the constructor.
     */
    @Override
    public EncryptionMaterials getEncryptionMaterials(EncryptionContext context) {
        return materials;
    }
    
    /**
     * Does nothing.
     */
    @Override
    public void refresh() {
        // Do Nothing
    }
}
