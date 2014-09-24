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

import com.amazonaws.services.dynamodbv2.datamodeling.encryption.EncryptionContext;
import com.amazonaws.services.dynamodbv2.datamodeling.encryption.materials.DecryptionMaterials;
import com.amazonaws.services.dynamodbv2.datamodeling.encryption.materials.EncryptionMaterials;

/**
 * Interface for providing encryption materials.
 * Implementations are free to use any strategy for providing encryption
 * materials, such as simply providing static material that doesn't change,
 * or more complicated implementations, such as integrating with existing
 * key management systems.
 * 
 * @author Greg Rubin 
 */
public interface EncryptionMaterialsProvider {

    /**
     * Retrieves encryption materials matching the specified description from some source.
     * 
     * @param context
     *      Information to assist in selecting a the proper return value. The implementation
     *      is free to determine the minimum necessary for successful processing.
     *
     * @return
     *      The encryption materials that match the description, or null if no matching encryption materials found.
     */
    public DecryptionMaterials getDecryptionMaterials(EncryptionContext context);

    /**
     * Returns EncryptionMaterials which the caller can use for encryption.
     * Each implementation of EncryptionMaterialsProvider can choose its own
     * strategy for loading encryption material.  For example, an
     * implementation might load encryption material from an existing key
     * management system, or load new encryption material when keys are
     * rotated.
     *
     * @param context
     *      Information to assist in selecting a the proper return value. The implementation
     *      is free to determine the minimum necessary for successful processing.
     *
     * @return EncryptionMaterials which the caller can use to encrypt or
     * decrypt data.
     */
    public EncryptionMaterials getEncryptionMaterials(EncryptionContext context);

    /**
     * Forces this encryption materials provider to refresh its encryption
     * material.  For many implementations of encryption materials provider,
     * this may simply be a no-op, such as any encryption materials provider
     * implementation that vends static/non-changing encryption material.
     * For other implementations that vend different encryption material
     * throughout their lifetime, this method should force the encryption
     * materials provider to refresh its encryption material.
     */
    public void refresh();
}
