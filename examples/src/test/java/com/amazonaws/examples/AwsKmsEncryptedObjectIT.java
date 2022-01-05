// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazonaws.examples;

import static com.amazonaws.examples.AwsKmsEncryptedObject.EXAMPLE_TABLE_NAME;
import static com.amazonaws.examples.AwsKmsEncryptedObject.PARTITION_ATTRIBUTE;
import static com.amazonaws.examples.AwsKmsEncryptedObject.SORT_ATTRIBUTE;
import static com.amazonaws.examples.TestUtils.US_WEST_2;
import static com.amazonaws.examples.TestUtils.US_WEST_2_KEY_ID;
import static com.amazonaws.examples.TestUtils.createDDBTable;

import com.amazonaws.services.dynamodbv2.AmazonDynamoDB;
import com.amazonaws.services.dynamodbv2.local.embedded.DynamoDBEmbedded;
import com.amazonaws.services.kms.AWSKMS;
import com.amazonaws.services.kms.AWSKMSClientBuilder;
import org.testng.annotations.Test;

public class AwsKmsEncryptedObjectIT {

  @Test
  public void testEncryptAndDecrypt() {
    final AWSKMS kms = AWSKMSClientBuilder.standard().withRegion(US_WEST_2).build();
    final AmazonDynamoDB ddb = DynamoDBEmbedded.create();

    // Create the table under test
    createDDBTable(ddb, EXAMPLE_TABLE_NAME, PARTITION_ATTRIBUTE, SORT_ATTRIBUTE);

    AwsKmsEncryptedObject.encryptRecord(US_WEST_2_KEY_ID, ddb, kms);
  }
}
