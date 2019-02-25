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

import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

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

/**
 * This demonstrates how to use the {@link DynamoDBMapper} with the {@link AttributeEncryptor}
 * to encrypt your data. Before you can use this you need to set up a table called "ExampleTable"
 * to hold the encrypted data.
 */
public class AwsKmsEncryptedObject {
  public static void main(String[] args) throws GeneralSecurityException {
    final String cmkArn = args[0];
    final String region = args[1];
    
    encryptRecord(cmkArn, region);
  }

  public static void encryptRecord(final String cmkArn, final String region) {
    // Sample object to be encrypted
    DataPoJo record = new DataPoJo();
    record.setPartitionAttribute("is this");
    record.setSortAttribute(55);
    record.setExample("data");
    record.setSomeNumbers(99);
    record.setSomeBinary(new byte[]{0x00, 0x01, 0x02});
    record.setLeaveMe("alone");

    // Set up our configuration and clients
    final AmazonDynamoDB ddb = AmazonDynamoDBClientBuilder.standard().withRegion(region).build();
    final AWSKMS kms = AWSKMSClientBuilder.standard().withRegion(region).build();
    final DirectKmsMaterialProvider cmp = new DirectKmsMaterialProvider(kms, cmkArn);
    // Encryptor creation
    final DynamoDBEncryptor encryptor = DynamoDBEncryptor.getInstance(cmp);
    // Mapper Creation
    // Please note the use of SaveBehavior.PUT (SaveBehavior.CLOBBER works as well).
    // Omitting this can result in data-corruption.
    DynamoDBMapperConfig mapperConfig = DynamoDBMapperConfig.builder().withSaveBehavior(SaveBehavior.PUT).build();
    DynamoDBMapper mapper = new DynamoDBMapper(ddb, mapperConfig, new AttributeEncryptor(encryptor));

    System.out.println("Plaintext Record: " + record);
    // Save the item to the DynamoDB table
    mapper.save(record);

    // Retrieve the encrypted item (directly without decrypting) from Dynamo so we can see it in our example
    final Map<String, AttributeValue> itemKey = new HashMap<>();
    itemKey.put("partition_attribute", new AttributeValue().withS("is this"));
    itemKey.put("sort_attribute", new AttributeValue().withN("55"));
    System.out.println("Encrypted Record: " + ddb.getItem("ExampleTable", itemKey).getItem());
    
    // Retrieve (and decrypt) it from DynamoDB
    DataPoJo decrypted_record = mapper.load(DataPoJo.class, "is this", 55);
    System.out.println("Decrypted Record: " + decrypted_record);
  }

  @DynamoDBTable(tableName = "ExampleTable")
  public static final class DataPoJo {
    private String partitionAttribute;
    private int sortAttribute;
    private String example;
    private long someNumbers;
    private byte[] someBinary;
    private String leaveMe;

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

    @DynamoDBAttribute(attributeName = "some numbers")
    public long getSomeNumbers() {
      return someNumbers;
    }

    public void setSomeNumbers(long someNumbers) {
      this.someNumbers = someNumbers;
    }

    @DynamoDBAttribute(attributeName = "and some binary")
    public byte[] getSomeBinary() {
      return someBinary;
    }

    public void setSomeBinary(byte[] someBinary) {
      this.someBinary = someBinary;
    }

    @DynamoDBAttribute(attributeName = "leave me")
    @DoNotTouch
    public String getLeaveMe() {
      return leaveMe;
    }

    public void setLeaveMe(String leaveMe) {
      this.leaveMe = leaveMe;
    }

    @Override
    public String toString() {
      return "DataPoJo [partitionAttribute=" + partitionAttribute + ", sortAttribute="
          + sortAttribute + ", example=" + example + ", someNumbers=" + someNumbers
          + ", someBinary=" + Arrays.toString(someBinary) + ", leaveMe=" + leaveMe + "]";
    }


  }
}
