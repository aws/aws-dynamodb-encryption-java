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

import com.amazonaws.services.dynamodbv2.datamodeling.AttributeEncryptor;
import com.amazonaws.services.dynamodbv2.datamodeling.DynamoDBAttribute;
import com.amazonaws.services.dynamodbv2.datamodeling.DynamoDBHashKey;
import com.amazonaws.services.dynamodbv2.datamodeling.DynamoDBIgnore;
import com.amazonaws.services.dynamodbv2.datamodeling.DynamoDBMapper;
import com.amazonaws.services.dynamodbv2.datamodeling.DynamoDBRangeKey;
import com.amazonaws.services.dynamodbv2.datamodeling.DynamoDBTable;
import com.amazonaws.services.dynamodbv2.datamodeling.encryption.DoNotTouch;

/**
 * This demonstrates how to use the {@link DynamoDBMapper} with the {@link AttributeEncryptor} to
 * encrypt your data. Before you can use this you need to set up a DynamoDB table called
 * "ExampleTable" to hold the encrypted data. "ExampleTable" should have a partition key named
 * "partition_attribute" for Strings and a sort (range) key named "sort_attribute" for numbers.
 */
public class AwsKmsEncryptedGlobal2017Object {
  public static final String EXAMPLE_TABLE_NAME = "ExampleTable";
  public static final String PARTITION_ATTRIBUTE = "partition_attribute";
  public static final String SORT_ATTRIBUTE = "sort_attribute";

  private static final String AWS_DYNAMODB_REPLICATION_DELETING_ATTRIBUTE = "aws:rep:deleting";
  private static final String AWS_DYNAMODB_REPLICATION_UPDATETIME_ATTRIBUTE = "aws:rep:updatetime";
  private static final String AWS_DYNAMODB_REPLICATION_UPDATEREGION_ATTRIBUTE = "aws:rep:updateregion";

  private static final String STRING_FIELD_NAME = "example";


  @DynamoDBTable(tableName = EXAMPLE_TABLE_NAME)
  public static final class DataPoJo {
    private String partitionAttribute;
    private int sortAttribute;
    private String example;
    private boolean aws_dynamodb_replication_deleting;
    private float aws_dynamodb_replication_updatetime;
    private String aws_dynamodb_replication_updateregion;

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


    @DynamoDBAttribute(attributeName = AWS_DYNAMODB_REPLICATION_DELETING_ATTRIBUTE)
    @DynamoDBIgnore
    @DoNotTouch
    public boolean getAws_dynamodb_replication_deleting() {
      return aws_dynamodb_replication_deleting;
    }
    public void setAws_dynamodb_replication_deleting(boolean deleting) {
      this.aws_dynamodb_replication_deleting = deleting;
    }

    @DynamoDBAttribute(attributeName = AWS_DYNAMODB_REPLICATION_UPDATETIME_ATTRIBUTE)
    @DynamoDBIgnore
    @DoNotTouch
    public float getAws_dynamodb_replication_updatetime() {
        return aws_dynamodb_replication_updatetime;
    }

    public void setAws_dynamodb_replication_updatetime(float updatetime) {
        this.aws_dynamodb_replication_updatetime = updatetime;
    }

    @DynamoDBAttribute(attributeName = AWS_DYNAMODB_REPLICATION_UPDATEREGION_ATTRIBUTE)
    @DynamoDBIgnore
    @DoNotTouch
    public String getAws_dynamodb_replication_updateregion() {
        return aws_dynamodb_replication_updateregion;
    }

    public void setAws_dynamodb_replication_updateregion(String updateregion) {
        this.aws_dynamodb_replication_updateregion = updateregion;
    }

    @Override
    public String toString() {
      return "DataPoJo [partitionAttribute="
          + partitionAttribute
          + ", sortAttribute="
          + sortAttribute
          + ", example="
          + example
          + "]";
    }
  }
}
