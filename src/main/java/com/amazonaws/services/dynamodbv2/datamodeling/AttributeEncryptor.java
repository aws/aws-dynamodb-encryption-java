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
package com.amazonaws.services.dynamodbv2.datamodeling;

import java.lang.reflect.Method;
import java.util.Collections;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import com.amazonaws.services.dynamodbv2.datamodeling.encryption.DoNotEncrypt;
import com.amazonaws.services.dynamodbv2.datamodeling.encryption.DoNotTouch;
import com.amazonaws.services.dynamodbv2.datamodeling.encryption.DynamoDBEncryptor;
import com.amazonaws.services.dynamodbv2.datamodeling.encryption.EncryptionContext;
import com.amazonaws.services.dynamodbv2.datamodeling.encryption.EncryptionFlags;
import com.amazonaws.services.dynamodbv2.datamodeling.encryption.providers.EncryptionMaterialsProvider;
import com.amazonaws.services.dynamodbv2.model.AttributeValue;

/**
 * Encrypts all non-key fields prior to storing them in DynamoDB.
 * 
 * @author Greg Rubin 
 */
public class AttributeEncryptor implements AttributeTransformer {
    private static final DynamoDBReflector reflector = new DynamoDBReflector();
    private final DynamoDBEncryptor encryptor;
    private final Map<Class<?>, Map<String, Set<EncryptionFlags>>> flagCache =
            new ConcurrentHashMap<Class<?>, Map<String, Set<EncryptionFlags>>>();

    public AttributeEncryptor(final DynamoDBEncryptor encryptor) {
        this.encryptor = encryptor;
    }

    public AttributeEncryptor(final EncryptionMaterialsProvider encryptionMaterialsProvider) {
        encryptor = DynamoDBEncryptor.getInstance(encryptionMaterialsProvider);
    }

    public DynamoDBEncryptor getEncryptor() {
        return encryptor;
    }

    @Override
    public Map<String, AttributeValue> transform(final Parameters<?> parameters) {
        // one map of attributeFlags per model class
        final Map<String, Set<EncryptionFlags>> attributeFlags = getAttributeFlags(parameters);
        try {
            return encryptor.encryptRecord(
                    parameters.getAttributeValues(),
                    attributeFlags,
                    paramsToContext(parameters));
        } catch (Exception ex) {
            throw new DynamoDBMappingException(ex);
        }
    }

    @Override
    public Map<String, AttributeValue> untransform(final Parameters<?> parameters) {
        final Map<String, Set<EncryptionFlags>> attributeFlags = getAttributeFlags(parameters);

        try {
            return encryptor.decryptRecord(
                    parameters.getAttributeValues(),
                    attributeFlags,
                    paramsToContext(parameters));
        } catch (Exception ex) {
            throw new DynamoDBMappingException(ex);
        }
    }

    private <T> Map<String, Set<EncryptionFlags>> getAttributeFlags(Parameters<T> parameters) {
        // Due to the lack of explicit synchronization, it is possible that
        // elements in the cache will be added multiple times. Since they will
        // all be identical, this is okay. Avoiding explicit synchronization
        // means that in the general (retrieval) case, should never block and
        // should be extremely fast.
        final Class<T> clazz = parameters.getModelClass();
        Map<String, Set<EncryptionFlags>> attributeFlags = flagCache.get(clazz);
        if (attributeFlags == null) {
            attributeFlags = new HashMap<String, Set<EncryptionFlags>>();

            final boolean encryptionEnabled = !clazz.isAnnotationPresent(DoNotEncrypt.class);
            final boolean doNotTouch = clazz.isAnnotationPresent(DoNotTouch.class);

            if (!doNotTouch) {
                final Method hashKeyGetter = reflector.getPrimaryHashKeyGetter(clazz);
                final Method rangeKeyGetter = reflector.getPrimaryRangeKeyGetter(clazz);

                for (Method getter : reflector.getRelevantGetters(clazz)) {
                    final EnumSet<EncryptionFlags> flags = EnumSet.noneOf(EncryptionFlags.class);
                    if (!getter.isAnnotationPresent(DoNotTouch.class)) {
                        if (encryptionEnabled && !getter.isAnnotationPresent(DoNotEncrypt.class)
                                && !getter.equals(hashKeyGetter) && !getter.equals(rangeKeyGetter)
                                && !reflector.isVersionAttributeGetter(getter)) {
                            flags.add(EncryptionFlags.ENCRYPT);
                        }
                        flags.add(EncryptionFlags.SIGN);
                    }
                    attributeFlags.put(reflector.getAttributeName(getter),
                            Collections.unmodifiableSet(flags));
                }
            }
            flagCache.put(clazz, Collections.unmodifiableMap(attributeFlags));
        }
        return attributeFlags;
    }
    
    private static EncryptionContext paramsToContext(Parameters<?> params) {
        return new EncryptionContext.Builder()
            .withHashKeyName(params.getHashKeyName())
            .withRangeKeyName(params.getRangeKeyName())
            .withTableName(params.getTableName())
            .withModeledClass(params.getModelClass())
            .withAttributeValues(params.getAttributeValues()).build();
    }
}
