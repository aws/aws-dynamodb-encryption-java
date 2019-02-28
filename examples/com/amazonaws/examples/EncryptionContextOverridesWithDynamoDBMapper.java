/*
 * Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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
package com.amazonaws.examples;

import com.amazonaws.services.dynamodbv2.AmazonDynamoDB;
import com.amazonaws.services.dynamodbv2.AmazonDynamoDBClientBuilder;
import com.amazonaws.services.dynamodbv2.datamodeling.AttributeEncryptor;
import com.amazonaws.services.dynamodbv2.datamodeling.DynamoDBAttribute;
import com.amazonaws.services.dynamodbv2.datamodeling.DynamoDBHashKey;
import com.amazonaws.services.dynamodbv2.datamodeling.DynamoDBMapper;
import com.amazonaws.services.dynamodbv2.datamodeling.DynamoDBMapperConfig;
import com.amazonaws.services.dynamodbv2.datamodeling.DynamoDBRangeKey;
import com.amazonaws.services.dynamodbv2.datamodeling.DynamoDBTable;
import com.amazonaws.services.dynamodbv2.datamodeling.encryption.DynamoDBEncryptor;
import com.amazonaws.services.dynamodbv2.datamodeling.encryption.EncryptionContext;
import com.amazonaws.services.dynamodbv2.datamodeling.encryption.EncryptionFlags;
import com.amazonaws.services.dynamodbv2.datamodeling.encryption.providers.DirectKmsMaterialProvider;
import com.amazonaws.services.dynamodbv2.model.AttributeValue;
import com.amazonaws.services.kms.AWSKMS;
import com.amazonaws.services.kms.AWSKMSClientBuilder;

import java.security.GeneralSecurityException;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import static com.amazonaws.services.dynamodbv2.datamodeling.encryption.utils.EncryptionContextOperators.overrideEncryptionContextTableNameUsingMap;

public class EncryptionContextOverridesWithDynamoDBMapper {
    public static void main(String[] args) throws GeneralSecurityException {
        final String cmkArn = args[0];
        final String region = args[1];
        final String encryptionContextTableName = args[2];

        AmazonDynamoDB ddb = null;
        AWSKMS kms = null;
        try {
            ddb = AmazonDynamoDBClientBuilder.standard().withRegion(region).build();
            kms = AWSKMSClientBuilder.standard().withRegion(region).build();
            encryptRecord(cmkArn, encryptionContextTableName, ddb, kms);
        } finally {
            if (ddb != null) {
                ddb.shutdown();
            }
            if (kms != null) {
                kms.shutdown();
            }
        }
    }

    public static void encryptRecord(final String cmkArn,
                                     final String newEncryptionContextTableName,
                                     AmazonDynamoDB ddb,
                                     AWSKMS kms) throws GeneralSecurityException {
        // Sample object to be encrypted
        ExampleItem record = new ExampleItem();
        record.setPartitionAttribute("is this");
        record.setSortAttribute(55);
        record.setExample("my data");

        // Set up our configuration and clients
        final DirectKmsMaterialProvider cmp = new DirectKmsMaterialProvider(kms, cmkArn);
        final DynamoDBEncryptor encryptor = DynamoDBEncryptor.getInstance(cmp);

        Map<String, String> tableNameEncryptionContextOverrides = new HashMap<>();
        tableNameEncryptionContextOverrides.put("ExampleTableForEncryptionContextOverrides", newEncryptionContextTableName);
        tableNameEncryptionContextOverrides.put("AnotherExampleTableForEncryptionContextOverrides", "this table doesn't exist");

        // Supply an operator to override the table name used in the encryption context
        encryptor.setEncryptionContextOverrideOperator(
                overrideEncryptionContextTableNameUsingMap(tableNameEncryptionContextOverrides)
        );

        // Mapper Creation
        // Please note the use of SaveBehavior.PUT (SaveBehavior.CLOBBER works as well).
        // Omitting this can result in data-corruption.
        DynamoDBMapperConfig mapperConfig = DynamoDBMapperConfig.builder()
                .withSaveBehavior(DynamoDBMapperConfig.SaveBehavior.PUT).build();
        DynamoDBMapper mapper = new DynamoDBMapper(ddb, mapperConfig, new AttributeEncryptor(encryptor));

        System.out.println("Plaintext Record: " + record.toString());
        // Save the record to the DynamoDB table
        mapper.save(record);

        // Retrieve (and decrypt) it from DynamoDB
        ExampleItem decrypted_record = mapper.load(ExampleItem.class, "is this", 55);
        System.out.println("Decrypted Record: " + decrypted_record.toString());

        // Setup new configuration to decrypt without using an overridden EncryptionContext
        final Map<String, AttributeValue> itemKey = new HashMap<>();
        itemKey.put("partition_attribute", new AttributeValue().withS("is this"));
        itemKey.put("sort_attribute", new AttributeValue().withN("55"));

        final EnumSet<EncryptionFlags> signOnly = EnumSet.of(EncryptionFlags.SIGN);
        final EnumSet<EncryptionFlags> encryptAndSign = EnumSet.of(EncryptionFlags.ENCRYPT, EncryptionFlags.SIGN);
        final Map<String, AttributeValue> encryptedItem = ddb.getItem("ExampleTableForEncryptionContextOverrides", itemKey)
                .getItem();
        System.out.println("Encrypted Record: " + encryptedItem);

        Map<String, Set<EncryptionFlags>> encryptionFlags = new HashMap<>();
        encryptionFlags.put("partition_attribute", signOnly);
        encryptionFlags.put("sort_attribute", signOnly);
        encryptionFlags.put("example", encryptAndSign);

        final DynamoDBEncryptor encryptorWithoutOverrides = DynamoDBEncryptor.getInstance(cmp);

        // Decrypt the record without using an overridden EncryptionContext
        encryptorWithoutOverrides.decryptRecord(encryptedItem,
                encryptionFlags,
                new EncryptionContext.Builder().withHashKeyName("partition_attribute")
                        .withRangeKeyName("sort_attribute")
                        .withTableName(newEncryptionContextTableName)
                        .build());
        System.out.printf("The example item was encrypted using the table name '%s' in the EncryptionContext%n", newEncryptionContextTableName);
    }

    @DynamoDBTable(tableName = "ExampleTableForEncryptionContextOverrides")
    public static final class ExampleItem {
        private String partitionAttribute;
        private int sortAttribute;
        private String example;

        @DynamoDBHashKey(attributeName = "partition_attribute")
        public String getPartitionAttribute() {
            return partitionAttribute;
        }

        public void setPartitionAttribute(String partitionAttribute) {
            this.partitionAttribute = partitionAttribute;
        }

        @DynamoDBRangeKey(attributeName = "sort_attribute")
        public int getSortAttribute() {
            return sortAttribute;
        }

        public void setSortAttribute(int sortAttribute) {
            this.sortAttribute = sortAttribute;
        }

        @DynamoDBAttribute(attributeName = "example")
        public String getExample() {
            return example;
        }

        public void setExample(String example) {
            this.example = example;
        }

        public String toString() {
            return String.format("{partition_attribute: %s, sort_attribute: %s, example: %s}",
                    partitionAttribute, sortAttribute, example);
        }
    }

}
