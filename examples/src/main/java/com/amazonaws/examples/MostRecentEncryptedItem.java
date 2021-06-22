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

import com.amazonaws.services.dynamodbv2.AmazonDynamoDB;
import com.amazonaws.services.dynamodbv2.AmazonDynamoDBClientBuilder;
import com.amazonaws.services.dynamodbv2.datamodeling.encryption.DynamoDBEncryptor;
import com.amazonaws.services.dynamodbv2.datamodeling.encryption.EncryptionContext;
import com.amazonaws.services.dynamodbv2.datamodeling.encryption.EncryptionFlags;
import com.amazonaws.services.dynamodbv2.datamodeling.encryption.providers.CachingMostRecentProvider;
import com.amazonaws.services.dynamodbv2.datamodeling.encryption.providers.DirectKmsMaterialProvider;
import com.amazonaws.services.dynamodbv2.datamodeling.encryption.providers.store.MetaStore;
import com.amazonaws.services.dynamodbv2.model.AttributeValue;
import com.amazonaws.services.dynamodbv2.model.ProvisionedThroughput;
import com.amazonaws.services.kms.AWSKMS;
import com.amazonaws.services.kms.AWSKMSClientBuilder;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

/**
 * This demonstrates how to use the {@link CachingMostRecentProvider} backed by a {@link MetaStore}
 * and the {@link DirectKmsMaterialProvider} to encrypt your data. Before you can use this, you need
 * to set up a table to hold the intermediate keys or use --setup mode to construct the table once
 * and then re-run the example without the --setup mode
 */
public class MostRecentEncryptedItem {
  public static final String PARTITION_ATTRIBUTE = "partition_attribute";
  public static final String SORT_ATTRIBUTE = "sort_attribute";

  private static final String STRING_FIELD_NAME = "example";
  private static final String BINARY_FIELD_NAME = "and some binary";
  private static final String NUMBER_FIELD_NAME = "some numbers";
  private static final String IGNORED_FIELD_NAME = "leave me";

  public static void main(String[] args) throws GeneralSecurityException {
    final String mode = args[0];
    final String region = args[1];
    final String tableName = args[2];
    final String keyTableName = args[3];
    final String cmkArn = args[4];
    final String materialName = args[5];

    if (mode.equalsIgnoreCase("--setup")) {
      AmazonDynamoDB ddb = AmazonDynamoDBClientBuilder.standard().withRegion(region).build();
      MetaStore.createTable(ddb, keyTableName, new ProvisionedThroughput(1L, 1L));
      return;
    }

    AmazonDynamoDB ddb = null;
    AWSKMS kms = null;
    try {
      ddb = AmazonDynamoDBClientBuilder.standard().withRegion(region).build();
      kms = AWSKMSClientBuilder.standard().withRegion(region).build();
      encryptRecord(tableName, keyTableName, cmkArn, materialName, ddb, kms);
    } finally {
      if (ddb != null) {
        ddb.shutdown();
      }
      if (kms != null) {
        kms.shutdown();
      }
    }
  }

  public static void encryptRecord(
      String tableName,
      String keyTableName,
      String cmkArn,
      String materialName,
      AmazonDynamoDB ddbClient,
      AWSKMS kmsClient)
      throws GeneralSecurityException {
    // Sample record to be encrypted
    final Map<String, AttributeValue> record = new HashMap<>();
    record.put(PARTITION_ATTRIBUTE, new AttributeValue().withS("is this"));
    record.put(SORT_ATTRIBUTE, new AttributeValue().withN("55"));
    record.put(STRING_FIELD_NAME, new AttributeValue().withS("data"));
    record.put(NUMBER_FIELD_NAME, new AttributeValue().withN("99"));
    record.put(
        BINARY_FIELD_NAME,
        new AttributeValue().withB(ByteBuffer.wrap(new byte[] {0x00, 0x01, 0x02})));
    record.put(
        IGNORED_FIELD_NAME,
        new AttributeValue().withS("alone")); // We want to ignore this attribute

    // Set up our configuration and clients. All of this is thread-safe and can be reused across
    // calls.
    // Provider Configuration to protect the data keys
    // This example assumes we already have a DynamoDB client `ddbClient` and AWS KMS client
    // `kmsClient`
    final DirectKmsMaterialProvider kmsProv = new DirectKmsMaterialProvider(kmsClient, cmkArn);
    final DynamoDBEncryptor keyEncryptor = DynamoDBEncryptor.getInstance(kmsProv);
    final MetaStore metaStore = new MetaStore(ddbClient, keyTableName, keyEncryptor);
    // Provider configuration to protect the data
    final CachingMostRecentProvider cmp =
        new CachingMostRecentProvider(metaStore, materialName, 60_000);

    // Encryptor creation
    final DynamoDBEncryptor encryptor = DynamoDBEncryptor.getInstance(cmp);

    // Information about the context of our data (normally just Table information)
    final EncryptionContext encryptionContext =
        new EncryptionContext.Builder()
            .withTableName(tableName)
            .withHashKeyName(PARTITION_ATTRIBUTE)
            .withRangeKeyName(SORT_ATTRIBUTE)
            .build();

    // Describe what actions need to be taken for each attribute
    final EnumSet<EncryptionFlags> signOnly = EnumSet.of(EncryptionFlags.SIGN);
    final EnumSet<EncryptionFlags> encryptAndSign =
        EnumSet.of(EncryptionFlags.ENCRYPT, EncryptionFlags.SIGN);
    final Map<String, Set<EncryptionFlags>> actions = new HashMap<>();
    for (final String attributeName : record.keySet()) {
      switch (attributeName) {
        case PARTITION_ATTRIBUTE: // fall through
        case SORT_ATTRIBUTE:
          // Partition and sort keys must not be encrypted but should be signed
          actions.put(attributeName, signOnly);
          break;
        case IGNORED_FIELD_NAME:
          // For this example, we are neither signing nor encrypting this field
          break;
        default:
          // We want to encrypt and sign everything else
          actions.put(attributeName, encryptAndSign);
          break;
      }
    }
    // End set-up

    // Encrypt the plaintext record directly
    final Map<String, AttributeValue> encrypted_record =
        encryptor.encryptRecord(record, actions, encryptionContext);

    // Encrypted record fields change as expected
    assert encrypted_record.get(STRING_FIELD_NAME).getB()
        != null; // the encrypted string is stored as bytes
    assert encrypted_record.get(NUMBER_FIELD_NAME).getB()
        != null; // the encrypted number is stored as bytes
    assert !record
        .get(BINARY_FIELD_NAME)
        .getB()
        .equals(encrypted_record.get(BINARY_FIELD_NAME).getB()); // the encrypted bytes have updated
    assert record
        .get(IGNORED_FIELD_NAME)
        .getS()
        .equals(encrypted_record.get(IGNORED_FIELD_NAME).getS()); // ignored field is left as is

    // We could now put the encrypted item to DynamoDB just as we would any other item.
    // We're skipping it to to keep the example simpler.

    System.out.println("Plaintext Record: " + record);
    System.out.println("Encrypted Record: " + encrypted_record);

    // Decryption is identical. We'll pretend that we retrieved the record from DynamoDB.
    final Map<String, AttributeValue> decrypted_record =
        encryptor.decryptRecord(encrypted_record, actions, encryptionContext);
    System.out.println("Decrypted Record: " + decrypted_record);

    // The decrypted fields match the original fields before encryption
    assert record
        .get(STRING_FIELD_NAME)
        .getS()
        .equals(decrypted_record.get(STRING_FIELD_NAME).getS());
    assert record
        .get(NUMBER_FIELD_NAME)
        .getN()
        .equals(decrypted_record.get(NUMBER_FIELD_NAME).getN());
    assert record
        .get(BINARY_FIELD_NAME)
        .getB()
        .equals(decrypted_record.get(BINARY_FIELD_NAME).getB());
  }
}
