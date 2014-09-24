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

import java.security.Key;
import java.security.KeyPair;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.SecretKey;

/**
 * @author Greg Rubin 
 */
public abstract class AbstractRawMaterials implements DecryptionMaterials, EncryptionMaterials {
    private Map<String, String> description;
    private final Key signingKey;
    private final Key verificationKey;

    @SuppressWarnings("unchecked")
    protected AbstractRawMaterials(KeyPair signingPair) {
        this(signingPair, Collections.EMPTY_MAP);
    }

    protected AbstractRawMaterials(KeyPair signingPair, Map<String, String> description) {
        this.signingKey = signingPair.getPrivate();
        this.verificationKey = signingPair.getPublic();
        setMaterialDescription(description);
    }

    @SuppressWarnings("unchecked")
    protected AbstractRawMaterials(SecretKey macKey) {
        this(macKey, Collections.EMPTY_MAP);
    }

    protected AbstractRawMaterials(SecretKey macKey, Map<String, String> description) {
        this.signingKey = macKey;
        this.verificationKey = macKey;
        this.description = Collections.unmodifiableMap(new HashMap<String, String>(description));
    }

    @Override
    public Map<String, String> getMaterialDescription() {
        return new HashMap<String, String>(description);
    }

    public void setMaterialDescription(Map<String, String> description) {
        this.description = Collections.unmodifiableMap(new HashMap<String, String>(description));
    }

    @Override
    public Key getSigningKey() {
        return signingKey;
    }

    @Override
    public Key getVerificationKey() {
        return verificationKey;
    }
}
