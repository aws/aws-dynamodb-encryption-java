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

import com.amazonaws.services.dynamodbv2.datamodeling.DynamoDBMappingsRegistry.Mapping;
import com.amazonaws.services.dynamodbv2.datamodeling.DynamoDBMappingsRegistry.Mappings;
import com.amazonaws.services.dynamodbv2.datamodeling.encryption.DoNotEncrypt;
import com.amazonaws.services.dynamodbv2.datamodeling.encryption.DoNotTouch;
import com.amazonaws.services.dynamodbv2.datamodeling.encryption.DynamoDBEncryptor;
import com.amazonaws.services.dynamodbv2.datamodeling.encryption.EncryptionContext;
import com.amazonaws.services.dynamodbv2.datamodeling.encryption.EncryptionFlags;
import com.amazonaws.services.dynamodbv2.datamodeling.encryption.HandleUnknownAttributes;
import com.amazonaws.services.dynamodbv2.datamodeling.encryption.TableAadOverride;
import com.amazonaws.services.dynamodbv2.datamodeling.encryption.providers.EncryptionMaterialsProvider;
import com.amazonaws.services.dynamodbv2.model.AttributeValue;
import org.apache.commons.codec.digest.Crypt;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.util.Collections;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

/**
 * Encrypts all non-key fields prior to storing them in DynamoDB.
 * <em>This must be used with @{link SaveBehavior#PUT} or @{link SaveBehavior#CLOBBER}.</em>
 *
 * @author Greg Rubin
 */
public class AttributeEncryptor implements AttributeTransformer {
    private static final Log LOG = LogFactory.getLog(AttributeEncryptor.class);
    private final DynamoDBEncryptor encryptor;
    private final Map<Class<?>, CryptoMapperMetaData> metadataCache = new ConcurrentHashMap<>();

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
        final ModelClassMetadata metadata = getModelClassMetadata(parameters);

        final Map<String, AttributeValue> attributeValues = parameters.getAttributeValues();
        // If this class is marked as "DoNotTouch" then we know our encryptor will not change it at all
        // so we may as well fast-return and do nothing. This also avoids emitting errors when they would not apply.
        if (metadata.getDoNotTouch()) {
            return attributeValues;
        }

        // When AttributeEncryptor is used without SaveBehavior.PUT or CLOBBER, it is trying to transform only a subset
        // of the actual fields stored in DynamoDB. This means that the generated signature will not cover any
        // unmodified fields. Thus, upon untransform, the signature verification will fail as it won't cover all
        // expected fields.
        if (parameters.isPartialUpdate()) {
            throw new DynamoDBMappingException(
                    "Use of AttributeEncryptor without SaveBehavior.PUT or SaveBehavior.CLOBBER is an error " +
                            "and can result in data-corruption. This occured while trying to save " +
                            parameters.getModelClass());
        }

        try {
            return encryptor.encryptRecord(
                    attributeValues,
                    metadata.getEncryptionFlags(),
                    paramsToContext(parameters));
        } catch (Exception ex) {
            throw new DynamoDBMappingException(ex);
        }
    }

    @Override
    public Map<String, AttributeValue> untransform(final Parameters<?> parameters) {
        final Map<String, Set<EncryptionFlags>> attributeFlags = getEncryptionFlags(parameters);

        try {
            return encryptor.decryptRecord(
                    parameters.getAttributeValues(),
                    attributeFlags,
                    paramsToContext(parameters));
        } catch (Exception ex) {
            throw new DynamoDBMappingException(ex);
        }
    }

    /*
     * For any attributes we see from DynamoDB that aren't modeled in the mapper class,
     * we either ignore them (the default behavior), or include them for encryption/signing
     * based on the presence of the @HandleUnknownAttributes annotation (unless the class
     * has @DoNotTouch, then we don't include them).
     */
    private Map<String, Set<EncryptionFlags>> getEncryptionFlags(final Parameters<?> parameters) {
        final ModelClassMetadata metadata = getModelClassMetadata(parameters);

        // If the class is annotated with @DoNotTouch, then none of the attributes are
        // encrypted or signed, so we don't need to bother looking for unknown attributes.
        if (metadata.getDoNotTouch()) {
            return metadata.getEncryptionFlags();
        }

        final Set<EncryptionFlags> unknownAttributeBehavior = metadata.getUnknownAttributeBehavior();
        final Map<String, Set<EncryptionFlags>> attributeFlags = new HashMap<>();
        attributeFlags.putAll(metadata.getEncryptionFlags());

        for (final String attributeName : parameters.getAttributeValues().keySet()) {
            if (!attributeFlags.containsKey(attributeName) &&
                    !encryptor.getSignatureFieldName().equals(attributeName) &&
                    !encryptor.getMaterialDescriptionFieldName().equals(attributeName)) {

                attributeFlags.put(attributeName, unknownAttributeBehavior);
            }
        }

        return attributeFlags;
    }

    private <T> ModelClassMetadata getModelClassMetadata(Parameters<T> parameters) {
        // Due to the lack of explicit synchronization, it is possible that
        // elements in the cache will be added multiple times. Since they will
        // all be identical, this is okay. Avoiding explicit synchronization
        // means that in the general (retrieval) case, should never block and
        // should be extremely fast.
        final Class<T> clazz = parameters.getModelClass();
        return getModelClassMetadata(clazz);
    }

    private <T> CryptoMapperMetaData getModelClassMetadata(Class<T> clazz) {
        CryptoMapperMetaData metadata = metadataCache.get(clazz);

        if (metadata == null) {
            Map<String, Set<EncryptionFlags>> attributeFlags = new HashMap<>();

            final boolean handleUnknownAttributes = handleUnknownAttributes(clazz);
            final EnumSet<EncryptionFlags> unknownAttributeBehavior = EnumSet.noneOf(EncryptionFlags.class);

            if (shouldTouch(clazz)) {
                Mappings mappings = DynamoDBMappingsRegistry.instance().mappingsOf(clazz);

                for (Mapping mapping : mappings.getMappings()) {
                    final EnumSet<EncryptionFlags> flags = EnumSet.noneOf(EncryptionFlags.class);
                    StandardAnnotationMaps.FieldMap<?> fieldMap = StandardAnnotationMaps.of(mapping.getter(), null);
                    if (shouldTouch(fieldMap)) {
                        if (shouldEncryptAttribute(clazz, mapping, fieldMap)) {
                            flags.add(EncryptionFlags.ENCRYPT);
                        }
                        flags.add(EncryptionFlags.SIGN);
                    }
                    attributeFlags.put(mapping.getAttributeName(), Collections.unmodifiableSet(flags));
                }

                if (handleUnknownAttributes) {
                    unknownAttributeBehavior.add(EncryptionFlags.SIGN);

                    if (shouldEncrypt(clazz)) {
                        unknownAttributeBehavior.add(EncryptionFlags.ENCRYPT);
                    }
                }
            }

            metadata = new CryptoMapperMetaData(
                    Collections.unmodifiableMap(attributeFlags),
                    doNotTouch(clazz),
                    Collections.unmodifiableSet(unknownAttributeBehavior)
            );
            metadataCache.put(clazz, metadata);
        }
        return metadata;
    }

    /**
     * @return True if {@link DoNotTouch} is not present on the class level. False otherwise
     */
    private boolean shouldTouch(Class<?> clazz) {
        return !doNotTouch(clazz);
    }

    /**
     * @return True if {@link DoNotTouch} is not present on the getter level. False otherwise.
     */
    private boolean shouldTouch(StandardAnnotationMaps.FieldMap<?> fieldMap) {
        return !doNotTouch(fieldMap);
    }

    /**
     * @return True if {@link DoNotTouch} IS present on the class level. False otherwise.
     */
    private boolean doNotTouch(Class<?> clazz) {
        return clazz.isAnnotationPresent(DoNotTouch.class);
    }

    /**
     * @return True if {@link DoNotTouch} IS present on the getter level. False otherwise.
     */
    private boolean doNotTouch(StandardAnnotationMaps.FieldMap<?> fieldMap) {
        return fieldMap.actualOf(DoNotTouch.class) != null;
    }

    /**
     * @return True if {@link DoNotEncrypt} is NOT present on the class level. False otherwise.
     */
    private boolean shouldEncrypt(Class<?> clazz) {
        return !doNotEncrypt(clazz);
    }

    /**
     * @return True if {@link DoNotEncrypt} IS present on the class level. False otherwise.
     */
    private boolean doNotEncrypt(Class<?> clazz) {
        return clazz.isAnnotationPresent(DoNotEncrypt.class);
    }

    /**
     * @return True if {@link DoNotEncrypt} IS present on the getter level. False otherwise.
     */
    private boolean doNotEncrypt(StandardAnnotationMaps.FieldMap<?> fieldMap) {
        return fieldMap.actualOf(DoNotEncrypt.class) != null;
    }

    /**
     * @return True if the attribute should be encrypted, false otherwise.
     */
    private boolean shouldEncryptAttribute(
            final Class<?> clazz,
            final Mapping mapping,
            final StandardAnnotationMaps.FieldMap<?> fieldMap) {

        return !(doNotEncrypt(clazz) || doNotEncrypt(fieldMap) || mapping.isPrimaryKey() || mapping.isVersion());
    }

    private static EncryptionContext paramsToContext(Parameters<?> params) {
        final Class<?> clazz = params.getModelClass();
        final TableAadOverride override = clazz.getAnnotation(TableAadOverride.class);
        final String tableName = ((override == null) ? params.getTableName() : override.tableName());

        return new EncryptionContext.Builder()
                .withHashKeyName(params.getHashKeyName())
                .withRangeKeyName(params.getRangeKeyName())
                .withTableName(tableName)
                .withModeledClass(params.getModelClass())
                .withAttributeValues(params.getAttributeValues()).build();
    }

    private boolean handleUnknownAttributes(Class<?> clazz) {
        return clazz.getAnnotation(HandleUnknownAttributes.class) != null;
    }

    public <T> CryptoMapperMetaData metaData(Class<T> dynamoModel) {
        return getModelClassMetadata(dynamoModel);
    }


}
