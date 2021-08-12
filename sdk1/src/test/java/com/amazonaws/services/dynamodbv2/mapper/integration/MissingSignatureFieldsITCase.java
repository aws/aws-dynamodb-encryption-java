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
import static org.testng.Assert.assertNull;
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
  private static final String STRING_ATTRIBUTE = "stringAttribute";
  private static Map<String, AttributeValue> plaintextItem = new HashMap<>();
  private static Map<String, AttributeValue> encryptedItem = new HashMap<>();
  private static Map<String, AttributeValue> encryptedItemMissingSignature = new HashMap<>();
  private static Map<String, AttributeValue> encryptedItemMissingMatDesc = new HashMap<>();
  // Test data
  static {
    newArrayList(
            plaintextItem,
            encryptedItem,
            encryptedItemMissingSignature,
            encryptedItemMissingMatDesc)
        .forEach(
            attr -> {
              attr.put(KEY_NAME, new AttributeValue().withS("" + startKey++));
              attr.put(STRING_ATTRIBUTE, new AttributeValue().withS("" + startKey++));
            });
  }

  @BeforeClass
  public static void setUp() throws Exception {
    DynamoDBMapperCryptoIntegrationTestBase.setUp();
    DynamoDBEncryptor encryptor =
        DynamoDBEncryptor.getInstance(new TestEncryptionMaterialsProvider());
    EncryptionContext context =
        new EncryptionContext.Builder().withHashKeyName(KEY_NAME).withTableName(TABLE_NAME).build();
    // Insert the data
    dynamo.putItem(new PutItemRequest(TABLE_NAME, plaintextItem));

    encryptedItem = encryptor.encryptAllFieldsExcept(encryptedItem, context, KEY_NAME);
    dynamo.putItem(new PutItemRequest(TABLE_NAME, encryptedItem));

    encryptedItemMissingSignature =
        encryptor.encryptAllFieldsExcept(encryptedItemMissingSignature, context, KEY_NAME);
    encryptedItemMissingSignature.remove(encryptor.getSignatureFieldName());
    dynamo.putItem(new PutItemRequest(TABLE_NAME, encryptedItemMissingSignature));

    encryptedItemMissingMatDesc =
        encryptor.encryptAllFieldsExcept(encryptedItemMissingMatDesc, context, KEY_NAME);
    encryptedItemMissingMatDesc.remove(encryptor.getMaterialDescriptionFieldName());
    dynamo.putItem(new PutItemRequest(TABLE_NAME, encryptedItemMissingMatDesc));
  }

  @Test
  public void testLoadWithPlaintextItem() {
    DynamoDBMapper util = TestDynamoDBMapperFactory.createDynamoDBMapper(dynamo);
    UntouchedTable load = util.load(UntouchedTable.class, plaintextItem.get(KEY_NAME).getS());

    assertEquals(load.getKey(), plaintextItem.get(KEY_NAME).getS());
    assertEquals(load.getStringAttribute(), plaintextItem.get(STRING_ATTRIBUTE).getS());
  }

  @Test
  public void testLoadWithPlaintextItemWithModelHavingNewEncryptedAttribute() {
    DynamoDBMapper util = TestDynamoDBMapperFactory.createDynamoDBMapper(dynamo);
    UntouchedWithNewEncryptedAttributeTable load =
        util.load(
            UntouchedWithNewEncryptedAttributeTable.class, plaintextItem.get(KEY_NAME).getS());

    assertEquals(load.getKey(), plaintextItem.get(KEY_NAME).getS());
    assertEquals(load.getStringAttribute(), plaintextItem.get(STRING_ATTRIBUTE).getS());
    assertNull(load.getNewAttribute());
  }

  @Test(
      expectedExceptions = DynamoDBMappingException.class,
      expectedExceptionsMessageRegExp = "java.security.SignatureException: Bad signature")
  public void testLoadWithBadMissingSignatureField() {
    TestDynamoDBMapperFactory.createDynamoDBMapper(dynamo)
        .load(EncryptedTable.class, encryptedItemMissingSignature.get(KEY_NAME).getS());
  }

  @Test(
      expectedExceptions = DynamoDBMappingException.class,
      expectedExceptionsMessageRegExp = "java.security.SignatureException: Bad signature")
  public void testLoadWithBadMissingMaterialDescField() {
    TestDynamoDBMapperFactory.createDynamoDBMapper(dynamo)
        .load(EncryptedTable.class, encryptedItemMissingMatDesc.get(KEY_NAME).getS());
  }

  @Test(
      expectedExceptions = DynamoDBMappingException.class,
      expectedExceptionsMessageRegExp =
          "java.lang.IllegalArgumentException: Record did not contain encryption metadata fields: '\\*amzn-ddb-map-sig\\*', '\\*amzn-ddb-map-desc\\*'.")
  public void testLoadWithBadMissingSignatureNMaterialDescFields() {
    TestDynamoDBMapperFactory.createDynamoDBMapper(dynamo)
        .load(EncryptedTable.class, plaintextItem.get(KEY_NAME).getS());
  }

  @DynamoDBTable(tableName = "aws-java-sdk-util-crypto")
  public static class UntouchedTable {

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
      UntouchedTable that = (UntouchedTable) o;
      return key.equals(that.key) && stringAttribute.equals(that.stringAttribute);
    }
  }

  public static final class UntouchedWithNewEncryptedAttributeTable extends UntouchedTable {
    private String newAttribute;

    public String getNewAttribute() {
      return newAttribute;
    }

    public void setNewAttribute(String newAttribute) {
      this.newAttribute = newAttribute;
    }
  }

  public static final class EncryptedTable extends UntouchedTable {
    @Override
    @DynamoDBAttribute
    public String getStringAttribute() {
      return super.getStringAttribute();
    }
  }
}
