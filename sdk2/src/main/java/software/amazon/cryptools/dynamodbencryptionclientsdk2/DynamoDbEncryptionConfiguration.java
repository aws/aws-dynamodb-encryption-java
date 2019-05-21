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

import java.util.Map;

import software.amazon.cryptools.dynamodbencryptionclientsdk2.encryption.EncryptionContext;

/**
 * An interface to an object that supplies configuration and context to the {@link DynamoDbEncryptionClient}.
 */
public interface DynamoDbEncryptionConfiguration {
    /**
     * Get the default {@link EncryptionAction} that should be applied to any attribute that is found in the record and
     * does not have a specific override associated with it.
     * @return The default {@link EncryptionAction}.
     */
    EncryptionAction getDefaultEncryptionAction();

    /**
     * Gets a map of specific attribute {@link EncryptionAction} overrides.
     * @return A map of {@link EncryptionAction} overrides, keyed by attribute name.
     */
    Map<String, EncryptionAction> getEncryptionActionOverrides();

    /**
     * Returns an {@link EncryptionContext} to be used by the encryption client. Has information about the table
     * name, the names of the primary indices etc.
     * @return An {@link EncryptionContext} object.
     */
    EncryptionContext getEncryptionContext();

    /**
     * Default builder for an immutable implementation of {@link DynamoDbEncryptionConfiguration}.
     * @return A newly initialized {@link BasicDynamoDbEncryptionConfiguration.Builder}.
     */
    static BasicDynamoDbEncryptionConfiguration.Builder builder() {
        return new BasicDynamoDbEncryptionConfiguration.Builder();
    }
}
