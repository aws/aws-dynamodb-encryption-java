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

import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.cryptools.dynamodbencryptionclientsdk2.encryption.DynamoDbEncryptor;

/**
 * General interface for a class that is capable of encrypting and decrypting DynamoDB records as well as signing and
 * verifying signatures.
 */
public interface DynamoDbEncryptionClient {
    /**
     * Encrypt and sign a record.
     * @param itemAttributes The map of AttributeValues that make up the record.
     * @param configuration A {@link DynamoDbEncryptionConfiguration} object that configures the behavior and scope
     *                      of encryption and signing on the record.
     * @return A map of AttributeValues that has been encrypted and signed as directed.
     */
    Map<String, AttributeValue> encryptRecord(Map<String, AttributeValue> itemAttributes,
                                              DynamoDbEncryptionConfiguration configuration);

    /**
     * Decrypt and verify signature on a record.
     * @param itemAttributes The map of AttributeValues that make up the encrypted/signed record.
     * @param configuration A {@link DynamoDbEncryptionConfiguration} object that configures the behavior and scope
     *                      of decryption and signature verification on the record.
     * @return A map of AttributeValues that have been decrypted and verified as directed.
     */
    Map<String, AttributeValue> decryptRecord(Map<String, AttributeValue> itemAttributes,
                                              DynamoDbEncryptionConfiguration configuration);

    /**
     * Convenience method to return a builder for the default approved implementation of this interface, a
     * {@link DynamoDbEncryptor}.
     * @return A builder object for the default implementation of this interface.
     */
    static DynamoDbEncryptor.Builder builder() {
        return DynamoDbEncryptor.builder();
    }
}
