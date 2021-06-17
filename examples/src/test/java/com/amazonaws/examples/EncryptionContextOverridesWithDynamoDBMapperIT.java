// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazonaws.examples;

import static com.amazonaws.examples.EncryptionContextOverridesWithDynamoDBMapper.PARTITION_ATTRIBUTE;
import static com.amazonaws.examples.EncryptionContextOverridesWithDynamoDBMapper.SORT_ATTRIBUTE;
import static com.amazonaws.examples.EncryptionContextOverridesWithDynamoDBMapper.TABLE_NAME_TO_OVERRIDE;
import static com.amazonaws.examples.TestUtils.US_WEST_2;
import static com.amazonaws.examples.TestUtils.US_WEST_2_KEY_ID;
import static com.amazonaws.examples.TestUtils.createDDBTable;

import com.amazonaws.services.dynamodbv2.AmazonDynamoDB;
import com.amazonaws.services.dynamodbv2.local.embedded.DynamoDBEmbedded;
import com.amazonaws.services.kms.AWSKMS;
import com.amazonaws.services.kms.AWSKMSClientBuilder;
import java.security.GeneralSecurityException;
import org.testng.annotations.Test;

public class EncryptionContextOverridesWithDynamoDBMapperIT {
  private static final String OVERRIDE_TABLE_NAME = "java-ddbec-test-table-encctx-override-example";

  @Test
  public void testEncryptAndDecrypt() throws GeneralSecurityException {
    final AWSKMS kms = AWSKMSClientBuilder.standard().withRegion(US_WEST_2).build();
    final AmazonDynamoDB ddb = DynamoDBEmbedded.create();

    // Create the table under test
    createDDBTable(ddb, TABLE_NAME_TO_OVERRIDE, PARTITION_ATTRIBUTE, SORT_ATTRIBUTE);

    EncryptionContextOverridesWithDynamoDBMapper.encryptRecord(
        US_WEST_2_KEY_ID, OVERRIDE_TABLE_NAME, ddb, kms);
  }
}
