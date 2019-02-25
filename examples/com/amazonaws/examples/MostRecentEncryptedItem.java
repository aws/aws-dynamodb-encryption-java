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

import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import com.amazonaws.services.dynamodbv2.AmazonDynamoDB;
import com.amazonaws.services.dynamodbv2.AmazonDynamoDBClientBuilder;
import com.amazonaws.services.dynamodbv2.datamodeling.encryption.DynamoDBEncryptor;
import com.amazonaws.services.dynamodbv2.datamodeling.encryption.EncryptionContext;
import com.amazonaws.services.dynamodbv2.datamodeling.encryption.EncryptionFlags;
import com.amazonaws.services.dynamodbv2.datamodeling.encryption.providers.DirectKmsMaterialProvider;
import com.amazonaws.services.dynamodbv2.datamodeling.encryption.providers.MostRecentProvider;
import com.amazonaws.services.dynamodbv2.datamodeling.encryption.providers.store.MetaStore;
import com.amazonaws.services.dynamodbv2.model.AttributeValue;
import com.amazonaws.services.dynamodbv2.model.ProvisionedThroughput;
import com.amazonaws.services.kms.AWSKMS;
import com.amazonaws.services.kms.AWSKMSClientBuilder;

/**
 * This demonstrates how to use the {@link MostRecentProvider} backed by a
 * {@link MetaStore} and the {@link DirectKmsMaterialProvider} to encrypt
 * your data. Before you can use this, you need to set up a table to hold the
 * intermediate keys.
 */
public class MostRecentEncryptedItem {
 
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
    
    encryptRecord(tableName, keyTableName, region, cmkArn, materialName);
  }

  private static void encryptRecord(String tableName, String keyTableName, String region, String cmkArn, String materialName) throws GeneralSecurityException {
    // Sample record to be encrypted
    final String partitionKeyName = "partition_attribute";
    final String sortKeyName = "sort_attribute";
    final Map<String, AttributeValue> record = new HashMap<>();
    record.put(partitionKeyName, new AttributeValue().withS("is this"));
    record.put(sortKeyName, new AttributeValue().withN("55"));
    record.put("example", new AttributeValue().withS("data"));
    record.put("some numbers", new AttributeValue().withN("99"));
    record.put("and some binary", new AttributeValue().withB(ByteBuffer.wrap(new byte[]{0x00, 0x01, 0x02})));
    record.put("leave me", new AttributeValue().withS("alone")); // We want to ignore this attribute

    // Set up our configuration and clients. All of this is thread-safe and can be reused across calls.
    // Provider Configuration to protect the data keys
    final AmazonDynamoDB ddb = AmazonDynamoDBClientBuilder.standard().withRegion(region).build();
    final AWSKMS kms = AWSKMSClientBuilder.standard().withRegion(region).build();
    final DirectKmsMaterialProvider kmsProv = new DirectKmsMaterialProvider(kms, cmkArn);
    final DynamoDBEncryptor keyEncryptor = DynamoDBEncryptor.getInstance(kmsProv);
    final MetaStore metaStore = new MetaStore(ddb, keyTableName, keyEncryptor);
    //Provider configuration to protect the data
    final MostRecentProvider cmp = new MostRecentProvider(metaStore, materialName, 60_000);

    // Encryptor creation
    final DynamoDBEncryptor encryptor = DynamoDBEncryptor.getInstance(cmp);

    // Information about the context of our data (normally just Table information)
    final EncryptionContext encryptionContext = new EncryptionContext.Builder()
        .withTableName(tableName)
        .withHashKeyName(partitionKeyName)
        .withRangeKeyName(sortKeyName)
        .build();

    // Describe what actions need to be taken for each attribute
    final EnumSet<EncryptionFlags> signOnly = EnumSet.of(EncryptionFlags.SIGN);
    final EnumSet<EncryptionFlags> encryptAndSign = EnumSet.of(EncryptionFlags.ENCRYPT, EncryptionFlags.SIGN);
    final Map<String, Set<EncryptionFlags>> actions = new HashMap<>();
    for (final String attributeName : record.keySet()) {
      switch (attributeName) {
        case partitionKeyName: // fall through
        case sortKeyName:
          // Partition and sort keys must not be encrypted but should be signed
          actions.put(attributeName, signOnly);
          break;
        case "leave me":
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
    final Map<String, AttributeValue> encrypted_record = encryptor.encryptRecord(record, actions, encryptionContext);

    // We could now put the encrypted item to DynamoDB just as we would any other item.
    // We're skipping it to to keep the example simpler.

    System.out.println("Plaintext Record: " + record);
    System.out.println("Encrypted Record: " + encrypted_record);

    // Decryption is identical. We'll pretend that we retrieved the record from DynamoDB.
    final Map<String, AttributeValue> decrypted_record = encryptor.decryptRecord(encrypted_record, actions, encryptionContext);
    System.out.println("Decrypted Record: " + decrypted_record);
  }    
}
