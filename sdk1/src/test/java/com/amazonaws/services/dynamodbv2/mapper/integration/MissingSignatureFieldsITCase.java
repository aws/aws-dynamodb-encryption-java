/*
 * Copyright 2015 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"). You may not use this file except
 * in compliance with the License. A copy of the License is located at
 *
 * http://aws.amazon.com/apache2.0
 *
 * or in the "license" file accompanying this file. This file is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */
package com.amazonaws.services.dynamodbv2.mapper.integration;

import static org.testng.Assert.assertEquals;

import com.amazonaws.services.dynamodbv2.datamodeling.DynamoDBAttribute;
import com.amazonaws.services.dynamodbv2.datamodeling.DynamoDBHashKey;
import com.amazonaws.services.dynamodbv2.datamodeling.DynamoDBMapper;
import com.amazonaws.services.dynamodbv2.datamodeling.DynamoDBMappingException;
import com.amazonaws.services.dynamodbv2.datamodeling.DynamoDBTable;
import com.amazonaws.services.dynamodbv2.datamodeling.encryption.DoNotTouch;
import com.amazonaws.services.dynamodbv2.mapper.encryption.TestDynamoDBMapperFactory;
import com.amazonaws.services.dynamodbv2.model.AttributeValue;
import com.amazonaws.services.dynamodbv2.model.PutItemRequest;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

/** Test reading of document which does not contain signature field. */
public class MissingSignatureFieldsITCase extends DynamoDBMapperCryptoIntegrationTestBase {

  private static final String ORIGINAL_NAME_ATTRIBUTE = "originalName";
  private static final String STRING_ATTRIBUTE = "stringAttribute";
  private static final List<Map<String, AttributeValue>> attrs = new LinkedList<>();

  // Test data
  static {
    for (int i = 0; i < 5; i++) {
      Map<String, AttributeValue> attr = new HashMap<String, AttributeValue>();
      attr.put(KEY_NAME, new AttributeValue().withS("" + startKey++));
      attr.put(STRING_ATTRIBUTE, new AttributeValue().withS("" + startKey++));
      attr.put(ORIGINAL_NAME_ATTRIBUTE, new AttributeValue().withS("" + startKey++));
      attrs.add(attr);
    }
  }

  @BeforeClass
  public static void setUp() throws Exception {
    DynamoDBMapperCryptoIntegrationTestBase.setUp();
    for (Map<String, AttributeValue> attr : attrs) {
      dynamo.putItem(new PutItemRequest(TABLE_NAME, attr));
    }
  }

  @Test
  public void testLoadWithMissingSignatureFields() {
    DynamoDBMapper util = TestDynamoDBMapperFactory.createDynamoDBMapper(dynamo);

    for (Map<String, AttributeValue> attr : attrs) {
      AllDoNotTouchTable load = util.load(AllDoNotTouchTable.class, attr.get(KEY_NAME).getS());
      assertEquals(load.getKey(), attr.get(KEY_NAME).getS());
      assertEquals(load.getStringAttribute(), attr.get(STRING_ATTRIBUTE).getS());
    }
  }

  @Test(
      expectedExceptions = DynamoDBMappingException.class,
      expectedExceptionsMessageRegExp =
          "java.lang.IllegalArgumentException: Record did not contain encryption metadata fields: '\\*amzn-ddb-map-sig\\*', '\\*amzn-ddb-map-desc\\*'.")
  public void testLoadWithBadMissingSignatureFields() {
    TestDynamoDBMapperFactory.createDynamoDBMapper(dynamo)
        .load(EncryptedTable.class, attrs.get(0).get(KEY_NAME).getS());
  }

  @DynamoDBTable(tableName = "aws-java-sdk-util-crypto")
  public static class AllDoNotTouchTable {

    private String key;

    private String stringAttribute;

    @DynamoDBHashKey
    @DoNotTouch
    public String getKey() {
      return key;
    }

    public void setKey(String key) {
      this.key = key;
    }

    @DynamoDBAttribute
    @DoNotTouch
    public String getStringAttribute() {
      return stringAttribute;
    }

    public void setStringAttribute(String stringAttribute) {
      this.stringAttribute = stringAttribute;
    }

    @Override
    public boolean equals(Object o) {
      if (this == o) return true;
      if (o == null || getClass() != o.getClass()) return false;
      AllDoNotTouchTable that = (AllDoNotTouchTable) o;
      return key.equals(that.key) && stringAttribute.equals(that.stringAttribute);
    }
  }

  public static final class EncryptedTable extends AllDoNotTouchTable {
    @Override
    @DynamoDBAttribute
    public String getStringAttribute() {
      return super.getStringAttribute();
    }
  }
}
