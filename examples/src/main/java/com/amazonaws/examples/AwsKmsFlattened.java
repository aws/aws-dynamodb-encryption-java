package com.amazonaws.examples;

import com.amazonaws.examples.mapper.DateRange;
import com.amazonaws.examples.mapper.DateRangeSigned;
import com.amazonaws.examples.mapper.DateRangedDoNotTouch;
import com.amazonaws.examples.mapper.PojoWithFlattened;

import com.amazonaws.services.dynamodbv2.AmazonDynamoDB;
import com.amazonaws.services.dynamodbv2.AmazonDynamoDBClientBuilder;
import com.amazonaws.services.dynamodbv2.datamodeling.AttributeEncryptor;
import com.amazonaws.services.dynamodbv2.datamodeling.DynamoDBMapper;
import com.amazonaws.services.dynamodbv2.datamodeling.DynamoDBMapperConfig;
import com.amazonaws.services.dynamodbv2.model.AttributeValue;
import com.amazonaws.services.kms.AWSKMS;
import com.amazonaws.services.kms.AWSKMSClientBuilder;

import com.amazonaws.services.dynamodbv2.datamodeling.encryption.DynamoDBEncryptor;
import com.amazonaws.services.dynamodbv2.datamodeling.encryption.providers.DirectKmsMaterialProvider;

import java.security.GeneralSecurityException;
import java.util.Calendar;
import java.util.Date;
import java.util.logging.Logger;
import java.util.HashMap;
import java.util.Map;

import static com.amazonaws.examples.AwsKmsEncryptedObject.PARTITION_ATTRIBUTE;
import static com.amazonaws.examples.AwsKmsEncryptedObject.SORT_ATTRIBUTE;

public class AwsKmsFlattened {
  protected static Logger LOGGER = Logger.getLogger("AwsKmsFlattened");
  protected static final String PARTITION_VALUE = "PojoWithFlattened";
  protected static final int SORT_VALUE = 1689210272;

  public static void main(String[] args) throws GeneralSecurityException {
    final String tableName = args[0];
    final String cmkArn = args[1];
    final String region = args[2];

    AmazonDynamoDB ddb = null;
    AWSKMS kms = null;
    try {
      ddb = AmazonDynamoDBClientBuilder.standard().withRegion(region).build();
      kms = AWSKMSClientBuilder.standard().withRegion(region).build();
      encryptRecord(tableName, cmkArn, ddb, kms);
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
    final String tableName, final String cmkArn, final AmazonDynamoDB ddbClient, final AWSKMS kmsClient) {
    DateRange dateRange = new DateRange();
    Calendar calendar = Calendar.getInstance();
    calendar.set(2016, Calendar.JULY, 13);
    dateRange.setStart(calendar.getTime());
    dateRange.setEnd(new Date());
    PojoWithFlattened record = new PojoWithFlattened();
    record.setPartitionAttribute(PARTITION_VALUE);
    record.setSortAttribute(SORT_VALUE);
    record.setEncryptedRange(dateRange);
    record.setSignedRange(new DateRangeSigned(dateRange));
    record.setDoNotTouchRange(new DateRangedDoNotTouch(dateRange));

    final DirectKmsMaterialProvider cmp = new DirectKmsMaterialProvider(kmsClient, cmkArn);
    final DynamoDBEncryptor encryptor = DynamoDBEncryptor.getInstance(cmp);

    DynamoDBMapperConfig mapperConfig =
      DynamoDBMapperConfig.builder()
        .withSaveBehavior(DynamoDBMapperConfig.SaveBehavior.PUT)
        .withTableNameOverride(DynamoDBMapperConfig.TableNameOverride.withTableNameReplacement(tableName))
        .build();
    DynamoDBMapper mapper =
      new DynamoDBMapper(ddbClient, mapperConfig, new AttributeEncryptor(encryptor));

    LOGGER.severe("Plaintext Record: " + record);
    mapper.save(record);

    final Map<String, AttributeValue> itemKey = new HashMap<>();
    itemKey.put(PARTITION_ATTRIBUTE, new AttributeValue().withS(PARTITION_VALUE));
    itemKey.put(SORT_ATTRIBUTE, new AttributeValue().withN(String.format("%s", SORT_VALUE)));
    final Map<String, AttributeValue> encrypted_record =
      ddbClient.getItem(tableName, itemKey).getItem();

    LOGGER.severe("Encrypted Record: " + encrypted_record);

    // Assert the Encrypted Fields are in Bytes
    assert encrypted_record.get("encryptedStart").getB() != null;
    assert encrypted_record.get("encryptedEnd").getB() != null;
    // Assert the Signed & Ignored Fields are Strings
    assert encrypted_record.get("signedStart").getS() != null;
    assert encrypted_record.get("signedEnd").getS() != null;
    assert encrypted_record.get("doNotTouchStart").getS() != null;
    assert encrypted_record.get("doNotTouchEnd").getS() != null;

    PojoWithFlattened decrypted_record = mapper.load(PojoWithFlattened.class, PARTITION_VALUE, SORT_VALUE);
    LOGGER.severe("Decrypted Record: " + decrypted_record);

    assert record.getEncryptedRange().equals(decrypted_record.getEncryptedRange());

    // Assert Tampering a Nested Signed Field yields an Exception

  }
}
