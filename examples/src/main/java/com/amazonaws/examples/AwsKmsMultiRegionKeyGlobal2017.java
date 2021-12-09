// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazonaws.examples;

import com.amazonaws.services.dynamodbv2.AmazonDynamoDB;
import com.amazonaws.services.dynamodbv2.AmazonDynamoDBClientBuilder;
import com.amazonaws.services.dynamodbv2.datamodeling.AttributeEncryptor;
import com.amazonaws.services.dynamodbv2.datamodeling.DynamoDBMapper;
import com.amazonaws.services.dynamodbv2.datamodeling.DynamoDBMapperConfig;
import com.amazonaws.services.dynamodbv2.datamodeling.DynamoDBMapperConfig.TableNameOverride;
import com.amazonaws.services.dynamodbv2.datamodeling.encryption.DynamoDBEncryptor;
import com.amazonaws.services.dynamodbv2.datamodeling.encryption.providers.DirectKmsMaterialProvider;
import com.amazonaws.services.kms.AWSKMS;
import com.amazonaws.services.kms.AWSKMSClientBuilder;
import java.security.GeneralSecurityException;
import java.util.Random;

/**
 * Example showing use of AWS KMS CMP with an AWS KMS Multi-Region Key. We encrypt a record with a
 * key in one region, then decrypt the ciphertext with the same key replicated to another region.
 *
 * <p>This example assumes that you have a DDB Global Table replicated to two regions, and an AWS
 * KMS Multi-Region Key replicated to the same regions.
 */
public class AwsKmsMultiRegionKeyGlobal2017 {

  public static void main(String[] args) throws GeneralSecurityException {
    final String tableName = args[0];
    final String cmkArn1 = args[1];
    final String cmkArn2 = args[2];

    encryptAndDecrypt(tableName, cmkArn1, cmkArn2);
  }

  public static void encryptAndDecrypt(
      final String tableName, final String cmkArnEncrypt, final String cmkArnDecrypt)
      throws GeneralSecurityException {
    AWSKMS kmsDecrypt = null;
    AWSKMS kmsEncrypt = null;
    AmazonDynamoDB ddbEncrypt = null;
    AmazonDynamoDB ddbDecrypt = null;
    //noinspection DuplicatedCode
    try {
      Random random = new Random();
      int sort_value = random.nextInt();
      // Sample object to be encrypted
      AwsKmsEncryptedGlobal2017Object.DataPoJo record =
          new AwsKmsEncryptedGlobal2017Object.DataPoJo();
      record.setPartitionAttribute("is this");
      record.setSortAttribute(sort_value);
      record.setExample("data");

      // Set up clients and configuration in the first region. All of this is thread-safe and can be
      // reused
      // across calls
      final String encryptRegion = cmkArnEncrypt.split(":")[3];
      kmsEncrypt = AWSKMSClientBuilder.standard().withRegion(encryptRegion).build();
      ddbEncrypt = AmazonDynamoDBClientBuilder.standard().withRegion(encryptRegion).build();
      final DirectKmsMaterialProvider cmpEncrypt =
          new DirectKmsMaterialProvider(kmsEncrypt, cmkArnEncrypt);
      final DynamoDBEncryptor encryptor = DynamoDBEncryptor.getInstance(cmpEncrypt);

      // Mapper Creation
      // Please note the use of SaveBehavior.PUT (SaveBehavior.CLOBBER works as well).
      // Omitting this can result in data-corruption.
      DynamoDBMapperConfig mapperConfig =
          DynamoDBMapperConfig.builder()
              .withSaveBehavior(DynamoDBMapperConfig.SaveBehavior.PUT)
              .withTableNameOverride(TableNameOverride.withTableNameReplacement(tableName))
              .build();
      DynamoDBMapper encryptMapper =
          new DynamoDBMapper(ddbEncrypt, mapperConfig, new AttributeEncryptor(encryptor));

      System.out.println("Global 2017 Plaintext Record: " + record);
      // Save the item to the DynamoDB table
      encryptMapper.save(record);

      // DDB Global Table replication takes some time. Sleep for a moment to give the item a chance
      // to replicate
      // to the second region
      try {
        Thread.sleep(5000);
      } catch (InterruptedException ignored) {
      }

      // Set up clients and configuration in the second region
      final String decryptRegion = cmkArnDecrypt.split(":")[3];
      kmsDecrypt = AWSKMSClientBuilder.standard().withRegion(decryptRegion).build();
      ddbDecrypt = AmazonDynamoDBClientBuilder.standard().withRegion(decryptRegion).build();
      final DirectKmsMaterialProvider cmpDecrypt =
          new DirectKmsMaterialProvider(kmsDecrypt, cmkArnDecrypt);
      final DynamoDBEncryptor decryptor = DynamoDBEncryptor.getInstance(cmpDecrypt);

      DynamoDBMapper decryptMapper =
          new DynamoDBMapper(ddbDecrypt, mapperConfig, new AttributeEncryptor(decryptor));

      // Retrieve (and decrypt) it in the second region. This allows you to avoid a cross-region KMS
      // call to the
      // first region if your application is running in the second region
      AwsKmsEncryptedGlobal2017Object.DataPoJo decryptedRecord =
          decryptMapper.load(AwsKmsEncryptedGlobal2017Object.DataPoJo.class, "is this", sort_value);
      System.out.println("Global 2017 Decrypted Record: " + decryptedRecord);

      // The decrypted fields match the original fields before encryption
      assert record.getExample().equals(decryptedRecord.getExample());

      decryptedRecord.setExample("Howdy");
      encryptMapper.save(decryptedRecord);
      try {
        Thread.sleep(5000);
      } catch (InterruptedException ignored) {
      }
      AwsKmsEncryptedGlobal2017Object.DataPoJo decryptedRecordTwo =
          decryptMapper.load(AwsKmsEncryptedGlobal2017Object.DataPoJo.class, "is this", sort_value);
      System.out.println("Global 2017 Decrypted Record: " + decryptedRecord);
      assert decryptedRecordTwo.getExample().equals(decryptedRecord.getExample());

      encryptMapper.delete(decryptedRecordTwo);
    } finally {
      if (kmsDecrypt != null) {
        kmsDecrypt.shutdown();
      }
      if (kmsEncrypt != null) {
        kmsEncrypt.shutdown();
      }
      if (ddbEncrypt != null) {
        ddbEncrypt.shutdown();
      }
      if (ddbDecrypt != null) {
        ddbDecrypt.shutdown();
      }
    }
  }
}
