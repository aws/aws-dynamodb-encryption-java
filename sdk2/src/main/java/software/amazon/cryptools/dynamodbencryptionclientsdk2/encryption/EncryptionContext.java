/*
 * Copyright 2014-2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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
package software.amazon.cryptools.dynamodbencryptionclientsdk2.encryption;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import software.amazon.cryptools.dynamodbencryptionclientsdk2.encryption.materials.DecryptionMaterials;
import software.amazon.cryptools.dynamodbencryptionclientsdk2.encryption.materials.EncryptionMaterials;
import software.amazon.cryptools.dynamodbencryptionclientsdk2.encryption.providers.EncryptionMaterialsProvider;

import software.amazon.awssdk.services.dynamodb.model.AttributeValue;

/**
 * This class serves to provide additional useful data to
 * {@link EncryptionMaterialsProvider}s so they can more intelligently select
 * the proper {@link EncryptionMaterials} or {@link DecryptionMaterials} for
 * use. Any of the methods are permitted to return null.
 * <p>
 * For the simplest cases, all a developer needs to provide in the context are:
 * <ul>
 * <li>TableName</li>
 * <li>HashKeyName</li>
 * <li>RangeKeyName (if present)</li>
 * </ul>
 * 
 * This class is immutable.
 * 
 * @author Greg Rubin 
 */
public final class EncryptionContext {
    private final String tableName;
    private final Map<String, AttributeValue> attributeValues;
    private final Object developerContext;
    private final String hashKeyName;
    private final String rangeKeyName;
    private final Map<String, String> materialDescription;

    /**
     * Return a new builder that can be used to construct an {@link EncryptionContext}
     * @return A newly initialized {@link EncryptionContext.Builder}.
     */
    public static Builder builder() {
        return new Builder();
    }

    private EncryptionContext(Builder builder) {
        tableName = builder.tableName;
        attributeValues = builder.attributeValues;
        developerContext = builder.developerContext;
        hashKeyName = builder.hashKeyName;
        rangeKeyName = builder.rangeKeyName;
        materialDescription = builder.materialDescription;
    }
    
    /**
     * Returns the name of the DynamoDB Table this record is associated with.
     */
    public String getTableName() {
        return tableName;
    }
    
    /**
     * Returns the DynamoDB record about to be encrypted/decrypted.
     */
    public Map<String, AttributeValue> getAttributeValues() {
        return attributeValues;
    }
    
    /**
     * This object has no meaning (and will not be set or examined) by any core libraries.
     * It exists to allow custom object mappers and data access layers to pass
     * data to {@link EncryptionMaterialsProvider}s through the {@link DynamoDbEncryptor}.
     */
    public Object getDeveloperContext() {
        return developerContext;
    }
    
    /**
     * Returns the name of the HashKey attribute for the record to be encrypted/decrypted.
     */
    public String getHashKeyName() {
        return hashKeyName;
    }

    /**
     * Returns the name of the RangeKey attribute for the record to be encrypted/decrypted.
     */
    public String getRangeKeyName() {
        return rangeKeyName;
    }

    public Map<String, String> getMaterialDescription() {
        return materialDescription;
    }

    /**
     * Converts an existing {@link EncryptionContext} into a builder that can be used to mutate and make a new version.
     * @return A new {@link EncryptionContext.Builder} with all the fields filled out to match the current object.
     */
    public Builder toBuilder() {
        return new Builder(this);
    }
    
    /**
     * Builder class for {@link EncryptionContext}.
     * Mutable objects (other than <code>developerContext</code>) will undergo
     * a defensive copy prior to being stored in the builder.
     *
     * This class is <em>not</em> thread-safe.
     */
    public static final class Builder {
        private String tableName = null;
        private Map<String, AttributeValue> attributeValues = null;
        private Object developerContext = null;
        private String hashKeyName = null;
        private String rangeKeyName = null;
        private Map<String, String> materialDescription = null;

        private Builder() {
        }

        private Builder(EncryptionContext context) {
            tableName = context.getTableName();
            attributeValues = context.getAttributeValues();
            hashKeyName = context.getHashKeyName();
            rangeKeyName = context.getRangeKeyName();
            developerContext = context.getDeveloperContext();
            materialDescription = context.getMaterialDescription();
        }

        public EncryptionContext build() {
            return new EncryptionContext(this);
        }

        public Builder tableName(String tableName) {
            this.tableName = tableName;
            return this;
        }
        
        public Builder attributeValues(Map<String, AttributeValue> attributeValues) {
            this.attributeValues = Collections.unmodifiableMap(new HashMap<>(attributeValues));
            return this;
        }
        
        public Builder developerContext(Object developerContext) {
            this.developerContext = developerContext;
            return this;
        }
        
        public Builder hashKeyName(String hashKeyName) {
            this.hashKeyName = hashKeyName;
            return this;
        }
        
        public Builder rangeKeyName(String rangeKeyName) {
            this.rangeKeyName = rangeKeyName;
            return this;
        }
        
        public Builder materialDescription(Map<String, String> materialDescription) {
            this.materialDescription = Collections.unmodifiableMap(new HashMap<>(materialDescription));
            return this;
        }
    }

    @Override
    public String toString() {
        return "EncryptionContext [tableName=" + tableName + ", attributeValues=" + attributeValues
                + ", developerContext=" + developerContext
                + ", hashKeyName=" + hashKeyName + ", rangeKeyName=" + rangeKeyName
                + ", materialDescription=" + materialDescription + "]";
    }
}
