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
package com.amazonaws.services.dynamodbv2.mapper.encryption;

import com.amazonaws.services.dynamodbv2.datamodeling.encryption.EncryptionContext;
import com.amazonaws.services.dynamodbv2.datamodeling.encryption.materials.DecryptionMaterials;
import com.amazonaws.services.dynamodbv2.datamodeling.encryption.materials.EncryptionMaterials;
import com.amazonaws.services.dynamodbv2.datamodeling.encryption.providers.EncryptionMaterialsProvider;
import com.amazonaws.util.StringMapBuilder;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.util.Map;

public class TestEncryptionMaterialsProvider implements EncryptionMaterialsProvider {
    private final EncryptionMaterials em = new EncryptionMaterials() {
        @Override
        public Map<String, String> getMaterialDescription() {
            return new StringMapBuilder("id", "test").build();
        }

        @Override
        public SecretKey getEncryptionKey() {
            return new SecretKeySpec(new byte[32], "AES");
        }

        @Override
        public Key getSigningKey() {
            return new SecretKeySpec(new byte[32], "HmacSHA256");
        }
    };

    private final DecryptionMaterials dm = new DecryptionMaterials() {

        @Override
        public Map<String, String> getMaterialDescription() {
            return new StringMapBuilder("id", "test").build();
        }

        @Override
        public SecretKey getDecryptionKey() {
            return new SecretKeySpec(new byte[32], "AES");
        }

        @Override
        public Key getVerificationKey() {
            return new SecretKeySpec(new byte[32], "HmacSHA256");
        }
    };

    @Override
    public DecryptionMaterials getDecryptionMaterials(EncryptionContext context) {
        return dm;
    }

    @Override
    public EncryptionMaterials getEncryptionMaterials(EncryptionContext context) {
        return em;
    }

    @Override
    public void refresh() {
    }
}
