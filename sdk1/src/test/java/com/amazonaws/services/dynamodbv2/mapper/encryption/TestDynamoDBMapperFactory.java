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

import com.amazonaws.services.dynamodbv2.AmazonDynamoDB;
import com.amazonaws.services.dynamodbv2.datamodeling.AttributeEncryptor;
import com.amazonaws.services.dynamodbv2.datamodeling.DynamoDBMapper;
import com.amazonaws.services.dynamodbv2.datamodeling.DynamoDBMapperConfig;

public class TestDynamoDBMapperFactory {
    public static DynamoDBMapper createDynamoDBMapper(AmazonDynamoDB dynamo) {
        return new DynamoDBMapper(dynamo,
                DynamoDBMapperConfig.builder().withSaveBehavior(DynamoDBMapperConfig.SaveBehavior.PUT).build(),
                new AttributeEncryptor(new TestEncryptionMaterialsProvider()));
    }

    public static DynamoDBMapper createDynamoDBMapper(AmazonDynamoDB dynamo, DynamoDBMapperConfig config) {
        return new DynamoDBMapper(dynamo,
                config,
                new AttributeEncryptor(new TestEncryptionMaterialsProvider()));
    }
}
