// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazonaws.examples;

import static com.amazonaws.examples.MostRecentEncryptedItem.PARTITION_ATTRIBUTE;
import static com.amazonaws.examples.MostRecentEncryptedItem.SORT_ATTRIBUTE;
import static com.amazonaws.examples.TestUtils.*;

import com.amazonaws.services.dynamodbv2.AmazonDynamoDB;
import com.amazonaws.services.dynamodbv2.datamodeling.encryption.providers.store.MetaStore;
import com.amazonaws.services.dynamodbv2.local.embedded.DynamoDBEmbedded;
import com.amazonaws.services.dynamodbv2.model.ProvisionedThroughput;
import com.amazonaws.services.kms.AWSKMS;
import com.amazonaws.services.kms.AWSKMSClientBuilder;
import java.security.GeneralSecurityException;
import org.testng.annotations.Test;

public class MostRecentEncryptedItemIT {
  private static final String TABLE_NAME = "java-ddbec-test-table-mostrecent-example";
  private static final String KEY_TABLE_NAME = "java-ddbec-test-table-mostrecent-example-keys";
  private static final String MATERIAL_NAME = "testMaterial";

  @Test
  public void testEncryptAndDecrypt() throws GeneralSecurityException {
    final AWSKMS kms = AWSKMSClientBuilder.standard().withRegion(US_WEST_2).build();
    final AmazonDynamoDB ddb = DynamoDBEmbedded.create();

    // Create the key table under test
    MetaStore.createTable(ddb, KEY_TABLE_NAME, new ProvisionedThroughput(1L, 1L));

    // Create the table under test
    createDDBTable(ddb, TABLE_NAME, PARTITION_ATTRIBUTE, SORT_ATTRIBUTE);

    MostRecentEncryptedItem.encryptRecord(
        TABLE_NAME, KEY_TABLE_NAME, US_WEST_2_KEY_ID, MATERIAL_NAME, ddb, kms);
  }
}
