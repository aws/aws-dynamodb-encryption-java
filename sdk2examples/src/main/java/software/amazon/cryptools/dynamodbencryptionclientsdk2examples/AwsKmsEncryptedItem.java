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
package software.amazon.cryptools.dynamodbencryptionclientsdk2examples;

import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.awssdk.services.dynamodb.model.PutItemRequest;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.cryptools.dynamodbencryptionclientsdk2.DynamoDBEncryptor;
import software.amazon.cryptools.dynamodbencryptionclientsdk2.configuration.DynamoDBEncryptionConfiguration;
import software.amazon.cryptools.dynamodbencryptionclientsdk2.encryptioncontext.EncryptionContext;
import software.amazon.cryptools.dynamodbencryptionclientsdk2.providers.DirectKmsMaterialsProvider;

import java.util.HashMap;
import java.util.Map;

public class AwsKmsEncryptedItem {
    public static void main(String[] args) {
        KmsClient kmsClient = KmsClient.create();
        String arn = "";
        Map<String, String> description = new HashMap<>();
        String tableName = "ExampleTable";
        DynamoDbClient dynamoDbClient = DynamoDbClient.create();

        encryptRecord(kmsClient, dynamoDbClient, arn, description, tableName);
    }


    public static void encryptRecord(final KmsClient kmsClient,
                                     final DynamoDbClient dynamoDbClient,
                                     final String arn,
                                     final Map<String, String> description,
                                     final String tableName) {
        DirectKmsMaterialsProvider kmsMaterialsProvider = new DirectKmsMaterialsProvider(kmsClient, arn, description);
        DynamoDBEncryptor encryptor = new DynamoDBEncryptor(kmsMaterialsProvider);

        Map<String, AttributeValue> record = new HashMap<>();
        record.put("id", AttributeValue.builder().n("100").build());
        record.put("protectedName", AttributeValue.builder().s("Jeff").build());

        Map<String, AttributeValue> encryptedRecord = encryptor.encryptRecord(record,
                DynamoDBEncryptionConfiguration.builder()
                        .withEncryptionContext(EncryptionContext.builder()
                                .withTableName(tableName)
                                .withHashKeyName("id").build())
                        .build());

        PutItemRequest putItemRequest = PutItemRequest.builder()
                .item(encryptedRecord)
                .tableName(tableName)
                .build();

        dynamoDbClient.putItem(putItemRequest);
    }
}
