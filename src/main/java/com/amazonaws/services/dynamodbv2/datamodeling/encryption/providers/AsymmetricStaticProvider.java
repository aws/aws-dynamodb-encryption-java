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

/**
 * This is a thin wrapper around the {@link WrappedMaterialsProvider}, using
 * the provided <code>encryptionKey</code> for wrapping and unwrapping the
 * record key. Please see that class for detailed documentation.
 * 
 * @author Greg Rubin 
 */
public class AsymmetricStaticProvider extends WrappedMaterialsProvider {
    public AsymmetricStaticProvider(KeyPair encryptionKey, KeyPair signingPair) {
        this(encryptionKey, signingPair, Collections.<String, String>emptyMap());
    }
    
    public AsymmetricStaticProvider(KeyPair encryptionKey, SecretKey macKey) {
        this(encryptionKey, macKey, Collections.<String, String>emptyMap());
    }
    
    public AsymmetricStaticProvider(KeyPair encryptionKey, KeyPair signingPair, Map<String, String> description) {
        super(encryptionKey.getPublic(), encryptionKey.getPrivate(), signingPair, description);
    }

    public AsymmetricStaticProvider(KeyPair encryptionKey, SecretKey macKey, Map<String, String> description) {
        super(encryptionKey.getPublic(), encryptionKey.getPrivate(), macKey, description);
    }
}
