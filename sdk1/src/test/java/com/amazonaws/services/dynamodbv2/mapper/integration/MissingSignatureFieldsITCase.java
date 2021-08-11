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
import static org.testng.collections.Lists.newArrayList;

import com.amazonaws.services.dynamodbv2.datamodeling.DynamoDBAttribute;
import com.amazonaws.services.dynamodbv2.datamodeling.DynamoDBHashKey;
import com.amazonaws.services.dynamodbv2.datamodeling.DynamoDBMapper;
import com.amazonaws.services.dynamodbv2.datamodeling.DynamoDBMappingException;
import com.amazonaws.services.dynamodbv2.datamodeling.DynamoDBTable;
import com.amazonaws.services.dynamodbv2.datamodeling.encryption.DoNotTouch;
import com.amazonaws.services.dynamodbv2.datamodeling.encryption.DynamoDBEncryptor;
import com.amazonaws.services.dynamodbv2.datamodeling.encryption.EncryptionContext;
import com.amazonaws.services.dynamodbv2.mapper.encryption.TestDynamoDBMapperFactory;
import com.amazonaws.services.dynamodbv2.mapper.encryption.TestEncryptionMaterialsProvider;
import com.amazonaws.services.dynamodbv2.model.AttributeValue;
import com.amazonaws.services.dynamodbv2.model.PutItemRequest;

import java.util.HashMap;
import java.util.Map;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

/** Test reading of document which does not contain signature field. */
public class MissingSignatureFieldsITCase extends DynamoDBMapperCryptoIntegrationTestBase {

  private static final String ORIGINAL_NAME_ATTRIBUTE = "originalName";
  private static final String STRING_ATTRIBUTE = "stringAttribute";
  private static Map<String, AttributeValue> attrsWithNoEncryptionFlags = new HashMap<>();
  private static Map<String, AttributeValue> attrsWithEncryptionFlags = new HashMap<>();
  private static Map<String, AttributeValue> attrsWithMissingSignatureEncryptionFlag = new HashMap<>();
  private static Map<String, AttributeValue> attrsWithMissingMaterialDescEncryptionFlag = new HashMap<>();
  // Test data
  static {
    newArrayList(attrsWithNoEncryptionFlags,
            attrsWithEncryptionFlags,
            attrsWithMissingSignatureEncryptionFlag,
            attrsWithMissingMaterialDescEncryptionFlag)
            .forEach(attr -> {
                attr.put(KEY_NAME, new AttributeValue().withS("" + startKey++));
                attr.put(STRING_ATTRIBUTE, new AttributeValue().withS("" + startKey++));
                attr.put(ORIGINAL_NAME_ATTRIBUTE, new AttributeValue().withS("" + startKey++));
            });
  }

  @BeforeClass
  public static void setUp() throws Exception {
    System.setProperty("sqlite4java.library.path", "target/test-lib");
    DynamoDBMapperCryptoIntegrationTestBase.setUp();
    DynamoDBEncryptor encryptor =
            DynamoDBEncryptor.getInstance(new TestEncryptionMaterialsProvider());
    EncryptionContext context =
            new EncryptionContext.Builder().withHashKeyName(KEY_NAME).withTableName(TABLE_NAME).build();
    // Insert the data
    dynamo.putItem(new PutItemRequest(TABLE_NAME, attrsWithNoEncryptionFlags));

    attrsWithEncryptionFlags = encryptor.encryptAllFieldsExcept(attrsWithEncryptionFlags, context, KEY_NAME);
    dynamo.putItem(new PutItemRequest(TABLE_NAME, attrsWithEncryptionFlags));

    attrsWithMissingSignatureEncryptionFlag = encryptor.encryptAllFieldsExcept(attrsWithMissingSignatureEncryptionFlag, context, KEY_NAME);
    attrsWithMissingSignatureEncryptionFlag.remove(encryptor.getSignatureFieldName());
    dynamo.putItem(new PutItemRequest(TABLE_NAME, attrsWithMissingSignatureEncryptionFlag));

    attrsWithMissingMaterialDescEncryptionFlag = encryptor.encryptAllFieldsExcept(attrsWithMissingMaterialDescEncryptionFlag, context, KEY_NAME);
    attrsWithMissingSignatureEncryptionFlag.remove(encryptor.getMaterialDescriptionFieldName());
    dynamo.putItem(new PutItemRequest(TABLE_NAME, attrsWithMissingMaterialDescEncryptionFlag));
  }

  @Test
  public void testLoadWithMissingSignatureAndMaterialDescFields() {
    DynamoDBMapper util = TestDynamoDBMapperFactory.createDynamoDBMapper(dynamo);
    AllDoNotTouchTable load = util.load(AllDoNotTouchTable.class, attrsWithNoEncryptionFlags.get(KEY_NAME).getS());

    assertEquals(load.getKey(), attrsWithNoEncryptionFlags.get(KEY_NAME).getS());
    assertEquals(load.getStringAttribute(), attrsWithNoEncryptionFlags.get(STRING_ATTRIBUTE).getS());
  }

  @Test(
      expectedExceptions = DynamoDBMappingException.class,
      expectedExceptionsMessageRegExp = "java.security.SignatureException: Bad signature")
  public void testLoadWithBadMissingSignatureField() {
    TestDynamoDBMapperFactory.createDynamoDBMapper(dynamo)
            .load(EncryptedTable.class, attrsWithMissingSignatureEncryptionFlag.get(KEY_NAME).getS());
  }

  @Test(
          expectedExceptions = DynamoDBMappingException.class,
          expectedExceptionsMessageRegExp = "java.security.SignatureException: Bad signature")
  public void testLoadWithBadMissingMaterialDescField() {
    TestDynamoDBMapperFactory.createDynamoDBMapper(dynamo)
            .load(EncryptedTable.class, attrsWithMissingMaterialDescEncryptionFlag.get(KEY_NAME).getS());
  }

  @Test(
          expectedExceptions = DynamoDBMappingException.class,
          expectedExceptionsMessageRegExp = "java.lang.IllegalArgumentException: Record did not contain encryption metadata fields: '\\*amzn-ddb-map-sig\\*', '\\*amzn-ddb-map-desc\\*'.")
  public void testLoadWithBadMissingSignatureNMaterialDescFields() {
    TestDynamoDBMapperFactory.createDynamoDBMapper(dynamo)
            .load(EncryptedTable.class, attrsWithNoEncryptionFlags.get(KEY_NAME).getS());
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
