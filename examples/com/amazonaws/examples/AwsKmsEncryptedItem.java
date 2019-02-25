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

import com.amazonaws.services.dynamodbv2.datamodeling.encryption.DynamoDBEncryptor;
import com.amazonaws.services.dynamodbv2.datamodeling.encryption.EncryptionContext;
import com.amazonaws.services.dynamodbv2.datamodeling.encryption.EncryptionFlags;
import com.amazonaws.services.dynamodbv2.datamodeling.encryption.providers.DirectKmsMaterialProvider;
import com.amazonaws.services.dynamodbv2.model.AttributeValue;
import com.amazonaws.services.kms.AWSKMS;
import com.amazonaws.services.kms.AWSKMSClientBuilder;

/**
 * Example showing use of AWS KMS CMP with record encryption functions directly.
 */
public class AwsKmsEncryptedItem {
 
  public static void main(String[] args) throws GeneralSecurityException {
    final String tableName = args[0];
    final String cmkArn = args[1];
    final String region = args[2];
    
    encryptRecord(tableName, cmkArn, region);
  }

  private static void encryptRecord(String tableName, String cmkArn, String region) throws GeneralSecurityException {
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
    // Provider Configuration
    final AWSKMS kms = AWSKMSClientBuilder.standard().withRegion(region).build();
    final DirectKmsMaterialProvider cmp = new DirectKmsMaterialProvider(kms, cmkArn);
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
