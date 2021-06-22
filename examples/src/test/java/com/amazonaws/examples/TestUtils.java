package com.amazonaws.examples;

import static com.amazonaws.examples.AwsKmsEncryptedObject.*;

import com.amazonaws.services.dynamodbv2.AmazonDynamoDB;
import com.amazonaws.services.dynamodbv2.model.*;
import java.util.ArrayList;

public class TestUtils {
  private TestUtils() {
    throw new UnsupportedOperationException(
        "This class exists to hold static resources and cannot be instantiated.");
  }

  /**
   * These special test keys have been configured to allow Encrypt, Decrypt, and GenerateDataKey
   * operations from any AWS principal and should be used when adding new KMS tests.
   *
   * <p>This should go without saying, but never use these keys for production purposes (as anyone
   * in the world can decrypt data encrypted using them).
   */
  public static final String US_WEST_2_KEY_ID =
      "arn:aws:kms:us-west-2:658956600833:key/b3537ef1-d8dc-4780-9f5a-55776cbb2f7f";

  public static final String US_WEST_2 = "us-west-2";
  public static final String US_EAST_1_MRK_KEY_ID =
      "arn:aws:kms:us-east-1:658956600833:key/mrk-80bd8ecdcd4342aebd84b7dc9da498a7";
  public static final String US_WEST_2_MRK_KEY_ID =
      "arn:aws:kms:us-west-2:658956600833:key/mrk-80bd8ecdcd4342aebd84b7dc9da498a7";

  public static void createDDBTable(
      AmazonDynamoDB ddb, String tableName, String partitionName, String sortName) {
    ArrayList<AttributeDefinition> attrDef = new ArrayList<AttributeDefinition>();
    attrDef.add(
        new AttributeDefinition()
            .withAttributeName(partitionName)
            .withAttributeType(ScalarAttributeType.S));
    attrDef.add(
        new AttributeDefinition()
            .withAttributeName(sortName)
            .withAttributeType(ScalarAttributeType.N));

    ArrayList<KeySchemaElement> keySchema = new ArrayList<KeySchemaElement>();
    keySchema.add(
        new KeySchemaElement().withAttributeName(partitionName).withKeyType(KeyType.HASH));
    keySchema.add(new KeySchemaElement().withAttributeName(sortName).withKeyType(KeyType.RANGE));

    ddb.createTable(
        new CreateTableRequest()
            .withTableName(tableName)
            .withAttributeDefinitions(attrDef)
            .withKeySchema(keySchema)
            .withProvisionedThroughput(new ProvisionedThroughput(100L, 100L)));
  }
}
