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

import java.security.KeyPair;
import java.util.Collections;
import java.util.Map;

import javax.crypto.SecretKey;

/**
 * @author Greg Rubin 
 */
public class SymmetricRawMaterials extends AbstractRawMaterials {
    private final SecretKey cryptoKey;

    @SuppressWarnings("unchecked")
    public SymmetricRawMaterials(SecretKey encryptionKey, KeyPair signingPair) {
        this(encryptionKey, signingPair, Collections.EMPTY_MAP);
    }

    public SymmetricRawMaterials(SecretKey encryptionKey, KeyPair signingPair, Map<String, String> description) {
        super(signingPair, description);
        this.cryptoKey = encryptionKey;
    }

    @SuppressWarnings("unchecked")
    public SymmetricRawMaterials(SecretKey encryptionKey, SecretKey macKey) {
        this(encryptionKey, macKey, Collections.EMPTY_MAP);
    }

    public SymmetricRawMaterials(SecretKey encryptionKey, SecretKey macKey, Map<String, String> description) {
        super(macKey, description);
        this.cryptoKey = encryptionKey;
    }

    @Override
    public SecretKey getEncryptionKey() {
        return cryptoKey;
    }

    @Override
    public SecretKey getDecryptionKey() {
        return cryptoKey;
    }
}
