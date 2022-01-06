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
import com.amazonaws.services.dynamodbv2.datamodeling.DynamoDBMapperConfig.SaveBehavior;
import com.amazonaws.services.dynamodbv2.datamodeling.DynamoDBRangeKey;
import com.amazonaws.services.dynamodbv2.datamodeling.DynamoDBTable;
import com.amazonaws.services.dynamodbv2.datamodeling.encryption.DoNotTouch;
import com.amazonaws.services.dynamodbv2.datamodeling.encryption.DynamoDBEncryptor;
import com.amazonaws.services.dynamodbv2.datamodeling.encryption.providers.DirectKmsMaterialProvider;
import com.amazonaws.services.dynamodbv2.model.AttributeValue;
import com.amazonaws.services.kms.AWSKMS;
import com.amazonaws.services.kms.AWSKMSClientBuilder;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

/**
 * This demonstrates how to use the {@link DynamoDBMapper} with the {@link AttributeEncryptor} to
 * encrypt your data. Before you can use this you need to set up a DynamoDB table called
 * "ExampleTable" to hold the encrypted data. "ExampleTable" should have a partition key named
 * "partition_attribute" for Strings and a sort (range) key named "sort_attribute" for numbers.
 */
public class AwsKmsEncryptedObject {
  public static final String EXAMPLE_TABLE_NAME = "ExampleTable";
  public static final String PARTITION_ATTRIBUTE = "partition_attribute";
  public static final String SORT_ATTRIBUTE = "sort_attribute";

  private static final String STRING_FIELD_NAME = "example";
  private static final String BINARY_FIELD_NAME = "and some binary";
  private static final String NUMBER_FIELD_NAME = "some numbers";
  private static final String IGNORED_FIELD_NAME = "leave me";

  public static void main(String[] args) throws GeneralSecurityException {
    final String cmkArn = args[0];
    final String region = args[1];

    AmazonDynamoDB ddb = null;
    AWSKMS kms = null;
    try {
      ddb = AmazonDynamoDBClientBuilder.standard().withRegion(region).build();
      kms = AWSKMSClientBuilder.standard().withRegion(region).build();
      encryptRecord(cmkArn, ddb, kms);
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
      final String cmkArn, final AmazonDynamoDB ddbClient, final AWSKMS kmsClient) {
    // Sample object to be encrypted
    DataPoJo record = new DataPoJo();
    record.setPartitionAttribute("is this");
    record.setSortAttribute(55);
    record.setExample("data");
    record.setSomeNumbers(99);
    record.setSomeBinary(new byte[] {0x00, 0x01, 0x02});
    record.setLeaveMe("alone");

    // Set up our configuration and clients
    // This example assumes we already have a DynamoDB client `ddbClient` and AWS KMS client
    // `kmsClient`
    final DirectKmsMaterialProvider cmp = new DirectKmsMaterialProvider(kmsClient, cmkArn);
    // Encryptor creation
    final DynamoDBEncryptor encryptor = DynamoDBEncryptor.getInstance(cmp);
    // Mapper Creation
    // Please note the use of SaveBehavior.PUT (SaveBehavior.CLOBBER works as well).
    // Omitting this can result in data-corruption.
    DynamoDBMapperConfig mapperConfig =
        DynamoDBMapperConfig.builder().withSaveBehavior(SaveBehavior.PUT).build();
    DynamoDBMapper mapper =
        new DynamoDBMapper(ddbClient, mapperConfig, new AttributeEncryptor(encryptor));

    System.out.println("Plaintext Record: " + record);
    // Save the item to the DynamoDB table
    mapper.save(record);

    // Retrieve the encrypted item (directly without decrypting) from Dynamo so we can see it in our
    // example
    final Map<String, AttributeValue> itemKey = new HashMap<>();
    itemKey.put(PARTITION_ATTRIBUTE, new AttributeValue().withS("is this"));
    itemKey.put(SORT_ATTRIBUTE, new AttributeValue().withN("55"));
    final Map<String, AttributeValue> encrypted_record =
        ddbClient.getItem(EXAMPLE_TABLE_NAME, itemKey).getItem();
    System.out.println("Encrypted Record: " + encrypted_record);

    // Encrypted record fields change as expected
    assert encrypted_record.get(STRING_FIELD_NAME).getB()
        != null; // the encrypted string is stored as bytes
    assert encrypted_record.get(NUMBER_FIELD_NAME).getB()
        != null; // the encrypted number is stored as bytes
    assert !ByteBuffer.wrap(record.getSomeBinary())
        .equals(encrypted_record.get(BINARY_FIELD_NAME).getB()); // the encrypted bytes have updated
    assert record
        .getLeaveMe()
        .equals(encrypted_record.get(IGNORED_FIELD_NAME).getS()); // ignored field is left as is

    // Retrieve (and decrypt) it from DynamoDB
    DataPoJo decrypted_record = mapper.load(DataPoJo.class, "is this", 55);
    System.out.println("Decrypted Record: " + decrypted_record);

    // The decrypted fields match the original fields before encryption
    assert record.getExample().equals(decrypted_record.getExample());
    assert record.getSomeNumbers() == decrypted_record.getSomeNumbers();
    assert Arrays.equals(record.getSomeBinary(), decrypted_record.getSomeBinary());
  }

  @DynamoDBTable(tableName = EXAMPLE_TABLE_NAME)
  public static final class DataPoJo {
    private String partitionAttribute;
    private int sortAttribute;
    private String example;
    private long someNumbers;
    private byte[] someBinary;
    private String leaveMe;

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

    @DynamoDBAttribute(attributeName = NUMBER_FIELD_NAME)
    public long getSomeNumbers() {
      return someNumbers;
    }

    public void setSomeNumbers(long someNumbers) {
      this.someNumbers = someNumbers;
    }

    @DynamoDBAttribute(attributeName = BINARY_FIELD_NAME)
    public byte[] getSomeBinary() {
      return someBinary;
    }

    public void setSomeBinary(byte[] someBinary) {
      this.someBinary = someBinary;
    }

    @DynamoDBAttribute(attributeName = IGNORED_FIELD_NAME)
    @DoNotTouch
    public String getLeaveMe() {
      return leaveMe;
    }

    public void setLeaveMe(String leaveMe) {
      this.leaveMe = leaveMe;
    }

    @Override
    public String toString() {
      return "DataPoJo [partitionAttribute="
          + partitionAttribute
          + ", sortAttribute="
          + sortAttribute
          + ", example="
          + example
          + ", someNumbers="
          + someNumbers
          + ", someBinary="
          + Arrays.toString(someBinary)
          + ", leaveMe="
          + leaveMe
          + "]";
    }
  }
}
