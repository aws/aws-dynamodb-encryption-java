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
import java.security.Key;
import java.security.KeyPair;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.SecretKey;

import com.amazonaws.services.dynamodbv2.datamodeling.DynamoDBMappingException;
import com.amazonaws.services.dynamodbv2.datamodeling.encryption.EncryptionContext;
import com.amazonaws.services.dynamodbv2.datamodeling.encryption.materials.CryptographicMaterials;
import com.amazonaws.services.dynamodbv2.datamodeling.encryption.materials.DecryptionMaterials;
import com.amazonaws.services.dynamodbv2.datamodeling.encryption.materials.EncryptionMaterials;
import com.amazonaws.services.dynamodbv2.datamodeling.encryption.materials.WrappedRawMaterials;

/**
 * This provider will use create a unique (random) symmetric key upon each call to
 * {@link #getEncryptionMaterials(EncryptionContext)}. Practically, this means each record in DynamoDB will be
 * encrypted under a unique record key. A wrapped/encrypted copy of this record key is stored in the
 * MaterialsDescription field of that record and is unwrapped/decrypted upon reading that record.
 * 
 * This is generally a more secure way of encrypting data than with the
 * {@link SymmetricStaticProvider}.
 * 
 * @see WrappedRawMaterials
 * 
 * @author Greg Rubin 
 */
public class WrappedMaterialsProvider implements EncryptionMaterialsProvider {
    private final Key wrappingKey;
    private final Key unwrappingKey;
    private final KeyPair sigPair;
    private final SecretKey macKey;
    private final Map<String, String> description;

    /**
     * @param wrappingKey
     *            The key used to wrap/encrypt the symmetric record key. (May be the same as the
     *            <code>unwrappingKey</code>.)
     * @param unwrappingKey
     *            The key used to unwrap/decrypt the symmetric record key. (May be the same as the
     *            <code>wrappingKey</code>.) If null, then this provider may only be used for
     *            decryption, but not encryption.
     * @param signingPair
     *            the keypair used to sign/verify the data stored in Dynamo. If only the public key
     *            is provided, then this provider may only be used for decryption, but not
     *            encryption.
     */
    public WrappedMaterialsProvider(Key wrappingKey, Key unwrappingKey, KeyPair signingPair) {
        this(wrappingKey, unwrappingKey, signingPair, Collections.<String, String>emptyMap());
    }
    
    /**
     * @param wrappingKey
     *            The key used to wrap/encrypt the symmetric record key. (May be the same as the
     *            <code>unwrappingKey</code>.)
     * @param unwrappingKey
     *            The key used to unwrap/decrypt the symmetric record key. (May be the same as the
     *            <code>wrappingKey</code>.) If null, then this provider may only be used for
     *            decryption, but not encryption.
     * @param signingPair
     *            the keypair used to sign/verify the data stored in Dynamo. If only the public key
     *            is provided, then this provider may only be used for decryption, but not
     *            encryption.
     * @param description
     *            description the value to be returned by
     *            {@link CryptographicMaterials#getMaterialDescription()} for any
     *            {@link CryptographicMaterials} returned by this object.
     */
    public WrappedMaterialsProvider(Key wrappingKey, Key unwrappingKey, KeyPair signingPair, Map<String, String> description) {
        this.wrappingKey = wrappingKey;
        this.unwrappingKey = unwrappingKey;
        this.sigPair = signingPair;
        this.macKey = null;
        this.description = Collections.unmodifiableMap(new HashMap<String, String>(description));
    }

    /**
     * @param wrappingKey
     *            The key used to wrap/encrypt the symmetric record key. (May be the same as the
     *            <code>unwrappingKey</code>.)
     * @param unwrappingKey
     *            The key used to unwrap/decrypt the symmetric record key. (May be the same as the
     *            <code>wrappingKey</code>.) If null, then this provider may only be used for
     *            decryption, but not encryption.
     * @param macKey
     *            the key used to sign/verify the data stored in Dynamo.
     */
    public WrappedMaterialsProvider(Key wrappingKey, Key unwrappingKey, SecretKey macKey) {
        this(wrappingKey, unwrappingKey, macKey, Collections.<String, String>emptyMap());
    }
    
    /**
     * @param wrappingKey
     *            The key used to wrap/encrypt the symmetric record key. (May be the same as the
     *            <code>unwrappingKey</code>.)
     * @param unwrappingKey
     *            The key used to unwrap/decrypt the symmetric record key. (May be the same as the
     *            <code>wrappingKey</code>.) If null, then this provider may only be used for
     *            decryption, but not encryption.
     * @param macKey
     *            the key used to sign/verify the data stored in Dynamo.
     * @param description
     *            description the value to be returned by
     *            {@link CryptographicMaterials#getMaterialDescription()} for any
     *            {@link CryptographicMaterials} returned by this object.
     */
    public WrappedMaterialsProvider(Key wrappingKey, Key unwrappingKey, SecretKey macKey, Map<String, String> description) {
        this.wrappingKey = wrappingKey;
        this.unwrappingKey = unwrappingKey;
        this.sigPair = null;
        this.macKey = macKey;
        this.description = Collections.unmodifiableMap(new HashMap<String, String>(description));
    }

    @Override
    public DecryptionMaterials getDecryptionMaterials(EncryptionContext context) {
        try {
            if (macKey != null) {
                return new WrappedRawMaterials(wrappingKey, unwrappingKey, macKey, context.getMaterialDescription());
            } else {
                return new WrappedRawMaterials(wrappingKey, unwrappingKey, sigPair, context.getMaterialDescription());
            }
        } catch (GeneralSecurityException ex) {
            throw new DynamoDBMappingException("Unable to decrypt envelope key", ex);
        }
    }

    @Override
    public EncryptionMaterials getEncryptionMaterials(EncryptionContext context) {
        try {
            if (macKey != null) {
                return new WrappedRawMaterials(wrappingKey, unwrappingKey, macKey, description);
            } else {
                return new WrappedRawMaterials(wrappingKey, unwrappingKey, sigPair, description);
            }
        } catch (GeneralSecurityException ex) {
            throw new DynamoDBMappingException("Unable to encrypt envelope key", ex);
        }
    }
    
    @Override
    public void refresh() {
        // Do nothing
    }
}
