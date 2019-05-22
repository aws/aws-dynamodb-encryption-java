/*
 * Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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
package software.amazon.cryptools.dynamodbencryptionclientsdk2;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import software.amazon.cryptools.dynamodbencryptionclientsdk2.encryption.EncryptionContext;

public class BasicDynamoDbEncryptionConfiguration implements DynamoDbEncryptionConfiguration {
    private final EncryptionAction defaultEncryptionAction;
    private final Map<String, EncryptionAction> encryptionActionOverrides;
    private final EncryptionContext encryptionContext;

    private BasicDynamoDbEncryptionConfiguration(Builder builder) {
        this.defaultEncryptionAction = builder.defaultEncryptionAction;
        this.encryptionActionOverrides = Collections.unmodifiableMap(builder.encryptionActionOverrides);
        this.encryptionContext = builder.encryptionContext;
    }

    @Override
    public EncryptionAction getDefaultEncryptionAction() {
        return this.defaultEncryptionAction;
    }

    @Override
    public Map<String, EncryptionAction> getEncryptionActionOverrides() {
        return this.encryptionActionOverrides;
    }

    @Override
    public EncryptionContext getEncryptionContext() {
        return this.encryptionContext;
    }

    /**
     * Builder for an immutable implementation of {@link DynamoDbEncryptionConfiguration}.
     */
    public static class Builder {
        private EncryptionAction defaultEncryptionAction;
        private Map<String, EncryptionAction> encryptionActionOverrides = new HashMap<>();
        private EncryptionContext encryptionContext;

        /**
         * Set the default {@link EncryptionAction} that should be applied to any attribute that is found in the
         * record and does not have a specific override associated with it.
         * @param defaultEncryptionAction The default encryption action that should be applied to attributes.
         * @return a mutated instance of this builder.
         */
        public Builder defaultEncryptionAction(EncryptionAction defaultEncryptionAction) {
            this.defaultEncryptionAction = defaultEncryptionAction;
            return this;
        }

        /**
         * Add a map of encryption action overrides for specific attributes. Will be merged into any existing overrides
         * the builder already has and will overwrite existing values with the same key.
         * @param encryptionActionOverrides A map of encryption action overrides.
         * @return a mutated instance of this builder.
         */
        public Builder addEncryptionActionOverrides(Map<String, EncryptionAction> encryptionActionOverrides) {
            this.encryptionActionOverrides.putAll(encryptionActionOverrides);
            return this;
        }

        /**
         * Add a single encryption action override for a specific attribute. Will be merged into any existing overrides
         * ths builder already has and will overwrite existing values with the same key.
         * @param attributeKey The name of the attribute.
         * @param encryptionAction The encryption action to apply to that attribute.
         * @return a mutated instance of this builder.
         */
        public Builder addEncryptionActionOverride(String attributeKey, EncryptionAction encryptionAction) {
            this.encryptionActionOverrides.put(attributeKey, encryptionAction);
            return this;
        }

        /**
         * Sets the encryption context to be used by the encryption client when encrypting or decrypting records. At
         * a minimum the following fields should be set on the context: tableName, hashKeyName, rangeKeyName.
         * @param encryptionContext An {@link EncryptionContext} object to associate with this configuration.
         * @return a mutated instance of this builder.
         */
        public Builder encryptionContext(EncryptionContext encryptionContext) {
            this.encryptionContext = encryptionContext;
            return this;
        }

        /**
         * Construct an immutable {@link DynamoDbEncryptionConfiguration} from the information provided to the builder.
         * @return an initialized {@link BasicDynamoDbEncryptionConfiguration} object.
         */
        public BasicDynamoDbEncryptionConfiguration build() {
            return new BasicDynamoDbEncryptionConfiguration(this);
        }
    }
}
