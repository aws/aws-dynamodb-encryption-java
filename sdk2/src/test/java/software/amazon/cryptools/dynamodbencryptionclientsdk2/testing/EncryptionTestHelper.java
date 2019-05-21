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
package software.amazon.cryptools.dynamodbencryptionclientsdk2.testing;

import static java.util.stream.Collectors.toMap;
import static software.amazon.cryptools.dynamodbencryptionclientsdk2.EncryptionAction.ENCRYPT_AND_SIGN;
import static software.amazon.cryptools.dynamodbencryptionclientsdk2.EncryptionAction.SIGN_ONLY;

import java.util.Collection;
import java.util.Map;
import java.util.function.BiFunction;
import java.util.function.Function;

import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.cryptools.dynamodbencryptionclientsdk2.DynamoDbEncryptionClient;
import software.amazon.cryptools.dynamodbencryptionclientsdk2.DynamoDbEncryptionConfiguration;
import software.amazon.cryptools.dynamodbencryptionclientsdk2.encryption.EncryptionContext;

public final class EncryptionTestHelper {
    private EncryptionTestHelper() {
        // Static helper class
    }

    public static Map<String, AttributeValue> encryptAllFieldsExcept(DynamoDbEncryptionClient encryptionClient,
                                                                     Map<String, AttributeValue> record,
                                                                     EncryptionContext encryptionContext,
                                                                     Collection<String> overriddenFields) {
        return doSomethingExcept(encryptionClient::encryptRecord, record, encryptionContext, overriddenFields);
    }

    public static Map<String, AttributeValue> decryptAllFieldsExcept(DynamoDbEncryptionClient encryptionClient,
                                                                     Map<String, AttributeValue> record,
                                                                     EncryptionContext encryptionContext,
                                                                     Collection<String> overriddenFields) {
        return doSomethingExcept(encryptionClient::decryptRecord, record, encryptionContext, overriddenFields);
    }

    private static Map<String, AttributeValue> doSomethingExcept(
        BiFunction<Map<String, AttributeValue>, DynamoDbEncryptionConfiguration, Map<String, AttributeValue>> operation,
        Map<String, AttributeValue> record,
        EncryptionContext encryptionContext,
        Collection<String> overriddenFields) {

        DynamoDbEncryptionConfiguration encryptionConfiguration = DynamoDbEncryptionConfiguration.builder()
            .defaultEncryptionAction(ENCRYPT_AND_SIGN)
            .encryptionContext(encryptionContext)
            .addEncryptionActionOverrides(overriddenFields.stream().collect(toMap(Function.identity(),
                                                                                  ignored -> SIGN_ONLY)))
            .build();

        return operation.apply(record, encryptionConfiguration);
    }
}
