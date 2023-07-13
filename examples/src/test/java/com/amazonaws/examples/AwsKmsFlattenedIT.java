package com.amazonaws.examples;

import com.amazonaws.services.dynamodbv2.AmazonDynamoDB;
import com.amazonaws.services.dynamodbv2.AmazonDynamoDBClientBuilder;
import com.amazonaws.services.kms.AWSKMS;
import com.amazonaws.services.kms.AWSKMSClientBuilder;

import java.security.GeneralSecurityException;
import org.testng.annotations.Test;

import static com.amazonaws.examples.TestUtils.US_WEST_2;
import static com.amazonaws.examples.TestUtils.US_WEST_2_MRK_KEY_ID;

public class AwsKmsFlattenedIT {
  private static final String TABLE_NAME = "ddbec-mrk-testing";

  @Test
  public void testEncryptAndDecrypt() throws GeneralSecurityException {
    final AWSKMS kms = AWSKMSClientBuilder.standard().withRegion(US_WEST_2).build();
    final AmazonDynamoDB ddb = AmazonDynamoDBClientBuilder.standard().withRegion(US_WEST_2).build();
    AwsKmsFlattened.encryptRecord(TABLE_NAME, US_WEST_2_MRK_KEY_ID, ddb, kms);
  }
}
