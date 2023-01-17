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

import static com.amazonaws.services.dynamodbv2.datamodeling.encryption.utils.EncryptionContextOperators.overrideEncryptionContextTableNameUsingMap;

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

/**
 * This demonstrates how to use an operator to override the table name used in the encryption
 * context. Before you can use this you need to set up a DynamoDB table called
 * "ExampleTableForEncryptionContextOverrides" to hold the encrypted data.
 * "ExampleTableForEncryptionContextOverrides" should have a partition key named
 * "partition_attribute" for Strings and a sort (range) key named "sort_attribute" for numbers.
 */
public class EncryptionContextOverridesWithDynamoDBMapper {
  public static final String ORIGINAL_TABLE_NAME_TO_OVERRIDE = "ExampleTableForEncryptionContextOverrides";
  public static final String PARTITION_ATTRIBUTE = "partition_attribute";
  public static final String SORT_ATTRIBUTE = "sort_attribute";

  private static final String STRING_FIELD_NAME = "example";
  private static final String BINARY_FIELD_NAME = "and some binary";
  private static final String NUMBER_FIELD_NAME = "some numbers";
  private static final String IGNORED_FIELD_NAME = "leave me";

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

  public static void encryptRecord(
      final String cmkArn,
      final String currentTableName,
      AmazonDynamoDB ddbClient,
      AWSKMS kmsClient)
      throws GeneralSecurityException {
    // Sample object to be encrypted
    ExampleItem record = new ExampleItem();
    record.setPartitionAttribute("is this");
    record.setSortAttribute(55);
    record.setExample("my data");

    // Set up our configuration and clients
    // This example assumes we already have a DynamoDB client `ddbClient` and AWS KMS client
    // `kmsClient`
    final DirectKmsMaterialProvider cmp = new DirectKmsMaterialProvider(kmsClient, cmkArn);
    final DynamoDBEncryptor encryptor = DynamoDBEncryptor.getInstance(cmp);

    Map<String, String> tableNameEncryptionContextOverrides = new HashMap<>();
    tableNameEncryptionContextOverrides.put(ORIGINAL_TABLE_NAME_TO_OVERRIDE, currentTableName);
    tableNameEncryptionContextOverrides.put(
        "AnotherExampleTableForEncryptionContextOverrides", "this table doesn't exist");

    // Supply an operator to override the table name used in the encryption context
    encryptor.setEncryptionContextOverrideOperator(
        overrideEncryptionContextTableNameUsingMap(tableNameEncryptionContextOverrides));

    // Mapper Creation
    // Please note the use of SaveBehavior.PUT (SaveBehavior.CLOBBER works as well).
    // Omitting this can result in data-corruption.
    DynamoDBMapperConfig mapperConfig =
        DynamoDBMapperConfig.builder()
            .withSaveBehavior(DynamoDBMapperConfig.SaveBehavior.PUT)
            .build();
    DynamoDBMapper mapper =
        new DynamoDBMapper(ddbClient, mapperConfig, new AttributeEncryptor(encryptor));

    System.out.println("Plaintext Record: " + record.toString());
    // Save the record to the DynamoDB table
    mapper.save(record);

    // Retrieve (and decrypt) it from DynamoDB
    ExampleItem decrypted_record = mapper.load(ExampleItem.class, "is this", 55);
    System.out.println("Decrypted Record: " + decrypted_record.toString());

    // The decrypted field matches the original field before encryption
    assert record.getExample().equals(decrypted_record.getExample());

    // Setup new configuration to decrypt without using an overridden EncryptionContext
    final Map<String, AttributeValue> itemKey = new HashMap<>();
    itemKey.put(PARTITION_ATTRIBUTE, new AttributeValue().withS("is this"));
    itemKey.put(SORT_ATTRIBUTE, new AttributeValue().withN("55"));

    final EnumSet<EncryptionFlags> signOnly = EnumSet.of(EncryptionFlags.SIGN);
    final EnumSet<EncryptionFlags> encryptAndSign =
        EnumSet.of(EncryptionFlags.ENCRYPT, EncryptionFlags.SIGN);
    final Map<String, AttributeValue> encryptedItem =
        ddbClient.getItem(ORIGINAL_TABLE_NAME_TO_OVERRIDE, itemKey).getItem();
    System.out.println("Encrypted Record: " + encryptedItem);

    Map<String, Set<EncryptionFlags>> encryptionFlags = new HashMap<>();
    encryptionFlags.put(PARTITION_ATTRIBUTE, signOnly);
    encryptionFlags.put(SORT_ATTRIBUTE, signOnly);
    encryptionFlags.put(STRING_FIELD_NAME, encryptAndSign);

    final DynamoDBEncryptor encryptorWithoutOverrides = DynamoDBEncryptor.getInstance(cmp);

    // Decrypt the record without using an overridden EncryptionContext
    Map<String, AttributeValue> decrypted_without_override_record =
        encryptorWithoutOverrides.decryptRecord(
            encryptedItem,
            encryptionFlags,
            new EncryptionContext.Builder()
                .withHashKeyName(PARTITION_ATTRIBUTE)
                .withRangeKeyName(SORT_ATTRIBUTE)
                .withTableName(currentTableName)
                .build());
    System.out.printf(
        "The example item was encrypted using the table name '%s' in the EncryptionContext%n",
        currentTableName);

    // The decrypted field matches the original field before encryption
    assert record
        .getExample()
        .equals(decrypted_without_override_record.get(STRING_FIELD_NAME).getS());
  }

  @DynamoDBTable(tableName = ORIGINAL_TABLE_NAME_TO_OVERRIDE)
  public static final class ExampleItem {
    private String partitionAttribute;
    private int sortAttribute;
    private String example;

    @DynamoDBHashKey(attributeName = PARTITION_ATTRIBUTE)
    public String getPartitionAttribute() {
      return partitionAttribute;
    }

    public void setPartitionAttribute(String partitionAttribute) {
      this.partitionAttribute = partitionAttribute;
    }

    @DynamoDBRangeKey(attributeName = SORT_ATTRIBUTE)
    public int getSortAttribute() {
      return sortAttribute;
    }

    public void setSortAttribute(int sortAttribute) {
      this.sortAttribute = sortAttribute;
    }

    @DynamoDBAttribute(attributeName = STRING_FIELD_NAME)
    public String getExample() {
      return example;
    }

    public void setExample(String example) {
      this.example = example;
    }

    public String toString() {
      return String.format(
          "{partition_attribute: %s, sort_attribute: %s, example: %s}",
          partitionAttribute, sortAttribute, example);
    }
  }
}
