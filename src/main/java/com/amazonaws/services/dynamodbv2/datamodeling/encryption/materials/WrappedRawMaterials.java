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
package com.amazonaws.services.dynamodbv2.datamodeling.encryption.materials;

import com.amazonaws.services.dynamodbv2.datamodeling.encryption.DelegatedKey;
import com.amazonaws.services.dynamodbv2.datamodeling.internal.Base64;
import com.amazonaws.services.dynamodbv2.datamodeling.internal.Utils;

import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.util.Collections;
import java.util.Map;

/**
 * Represents cryptographic materials used to manage unique record-level keys.
 * This class specifically implements Envelope Encryption where a unique content
 * key is randomly generated each time this class is constructed which is then
 * encrypted with the Wrapping Key and then persisted in the Description. If a
 * wrapped key is present in the Description, then that content key is unwrapped
 * and used to decrypt the actual data in the record.
 * 
 * Other possibly implementations might use a Key-Derivation Function to derive
 * a unique key per record.
 *
 * @author Greg Rubin 
 */
public class WrappedRawMaterials extends AbstractRawMaterials {
    /**
     * The key-name in the Description which contains the algorithm use to wrap
     * content key. Example values are "AESWrap", or
     * "RSA/ECB/OAEPWithSHA-256AndMGF1Padding". 
     */
    public static final String KEY_WRAPPING_ALGORITHM = "amzn-ddb-wrap-alg";
    /**
     * The key-name in the Description which contains the algorithm used by the
     * content key. Example values are "AES", or "Blowfish".
     */
    public static final String CONTENT_KEY_ALGORITHM = "amzn-ddb-env-alg";
    /**
     * The key-name in the Description which which contains the wrapped content
     * key.
     */
    public  static final String ENVELOPE_KEY = "amzn-ddb-env-key";
    private static final String DEFAULT_ALGORITHM = "AES/256";

    protected final Key wrappingKey;
    protected final Key unwrappingKey;
    private final SecretKey envelopeKey;

    public WrappedRawMaterials(Key wrappingKey, Key unwrappingKey, KeyPair signingPair)
            throws GeneralSecurityException {
        this(wrappingKey, unwrappingKey, signingPair, Collections.<String, String>emptyMap());
    }

    public WrappedRawMaterials(Key wrappingKey, Key unwrappingKey, KeyPair signingPair,
            Map<String, String> description) throws GeneralSecurityException {
        super(signingPair, description);
        this.wrappingKey = wrappingKey;
        this.unwrappingKey = unwrappingKey;
        this.envelopeKey = initEnvelopeKey();
    }

    public WrappedRawMaterials(Key wrappingKey, Key unwrappingKey, SecretKey macKey)
            throws GeneralSecurityException {
        this(wrappingKey, unwrappingKey, macKey, Collections.<String, String>emptyMap());
    }

    public WrappedRawMaterials(Key wrappingKey, Key unwrappingKey, SecretKey macKey,
            Map<String, String> description) throws GeneralSecurityException {
        super(macKey, description);
        this.wrappingKey = wrappingKey;
        this.unwrappingKey = unwrappingKey;
        this.envelopeKey = initEnvelopeKey();
    }

    @Override
    public SecretKey getDecryptionKey() {
        return envelopeKey;
    }

    @Override
    public SecretKey getEncryptionKey() {
        return envelopeKey;
    }

    /**
     * Called by the constructors. If there is already a key associated with
     * this record (usually signified by a value stored in the description in
     * the key {@link #ENVELOPE_KEY}) it extracts it and returns it. Otherwise
     * it generates a new key, stores a wrapped version in the Description, and
     * returns the key to the caller.
     * 
     * @return the content key (which is returned by both
     *         {@link #getDecryptionKey()} and {@link #getEncryptionKey()}.
     * @throws GeneralSecurityException
     */
    protected SecretKey initEnvelopeKey() throws GeneralSecurityException {
        Map<String, String> description = getMaterialDescription();
        if (description.containsKey(ENVELOPE_KEY)) {
            if (unwrappingKey == null) {
                throw new IllegalStateException("No private decryption key provided.");
            }
            byte[] encryptedKey = Base64.decode(description.get(ENVELOPE_KEY));
            String wrappingAlgorithm = unwrappingKey.getAlgorithm();
            if (description.containsKey(KEY_WRAPPING_ALGORITHM)) {
                wrappingAlgorithm = description.get(KEY_WRAPPING_ALGORITHM);
            }
            return unwrapKey(description, encryptedKey, wrappingAlgorithm);
        } else {
            SecretKey key = description.containsKey(CONTENT_KEY_ALGORITHM) ?
                    generateContentKey(description.get(CONTENT_KEY_ALGORITHM)) :
                        generateContentKey(DEFAULT_ALGORITHM);
                        
            String wrappingAlg = description.containsKey(KEY_WRAPPING_ALGORITHM) ?
                    description.get(KEY_WRAPPING_ALGORITHM) :
                    getTransformation(wrappingKey.getAlgorithm());
            byte[] encryptedKey = wrapKey(key, wrappingAlg);
            description.put(ENVELOPE_KEY, Base64.encodeToString(encryptedKey));
            description.put(CONTENT_KEY_ALGORITHM, key.getAlgorithm());
            description.put(KEY_WRAPPING_ALGORITHM, wrappingAlg);
            setMaterialDescription(description);
            return key;
        }
    }

    public byte[] wrapKey(SecretKey key, String wrappingAlg) throws NoSuchAlgorithmException, NoSuchPaddingException,
            InvalidKeyException, IllegalBlockSizeException {
        if (wrappingKey instanceof DelegatedKey) {
            return ((DelegatedKey)wrappingKey).wrap(key, null, wrappingAlg);
        } else {
            Cipher cipher = Cipher.getInstance(wrappingAlg);
            cipher.init(Cipher.WRAP_MODE, wrappingKey, Utils.getRng());
            byte[] encryptedKey = cipher.wrap(key);
            return encryptedKey;
        }
    }

    protected SecretKey unwrapKey(Map<String, String> description, byte[] encryptedKey, String wrappingAlgorithm)
            throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException {
        if (unwrappingKey instanceof DelegatedKey) {
            return (SecretKey)((DelegatedKey)unwrappingKey).unwrap(encryptedKey,
                    description.get(CONTENT_KEY_ALGORITHM), Cipher.SECRET_KEY, null, wrappingAlgorithm);
        } else {
            Cipher cipher = Cipher.getInstance(wrappingAlgorithm);
            cipher.init(Cipher.UNWRAP_MODE, unwrappingKey, Utils.getRng());
            return (SecretKey) cipher.unwrap(encryptedKey,
                    description.get(CONTENT_KEY_ALGORITHM), Cipher.SECRET_KEY);
        }
    }
    
    protected SecretKey generateContentKey(final String algorithm) throws NoSuchAlgorithmException {
        String[] pieces = algorithm.split("/", 2);
        KeyGenerator kg = KeyGenerator.getInstance(pieces[0]);
        int keyLen = 0;
        if (pieces.length == 2) {
            try {
                keyLen = Integer.parseInt(pieces[1]);
            } catch (NumberFormatException ex) {
                keyLen = 0;
            }
        }
        
        if (keyLen > 0) {
            kg.init(keyLen, Utils.getRng());
        } else {
            kg.init(Utils.getRng());
        }
        return kg.generateKey();
    }
    
    private static String getTransformation(final String algorithm) {
        if (algorithm.equalsIgnoreCase("RSA")) {
            return "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";
        } else if (algorithm.equalsIgnoreCase("AES")) {
            return "AESWrap";
        } else {
            return algorithm;
        }
    }
}
