package com.amazonaws.examples;

import com.amazonaws.services.dynamodbv2.AmazonDynamoDB;
import com.amazonaws.services.dynamodbv2.AmazonDynamoDBClientBuilder;
import com.amazonaws.services.dynamodbv2.datamodeling.AttributeEncryptor;
import com.amazonaws.services.dynamodbv2.datamodeling.DynamoDBAttribute;
import com.amazonaws.services.dynamodbv2.datamodeling.DynamoDBHashKey;
import com.amazonaws.services.dynamodbv2.datamodeling.DynamoDBMapper;
import com.amazonaws.services.dynamodbv2.datamodeling.DynamoDBMapperConfig;
import com.amazonaws.services.dynamodbv2.datamodeling.DynamoDBTable;
import com.amazonaws.services.dynamodbv2.datamodeling.encryption.DynamoDBEncryptor;
import com.amazonaws.services.dynamodbv2.datamodeling.encryption.providers.DirectKmsMaterialProvider;
import com.amazonaws.services.dynamodbv2.datamodeling.encryption.utils.EncryptionContextOperators;
import com.amazonaws.services.dynamodbv2.model.AttributeValue;
import com.amazonaws.services.dynamodbv2.model.GetItemRequest;
import com.amazonaws.services.dynamodbv2.model.GetItemResult;
import com.amazonaws.services.dynamodbv2.model.PutItemRequest;
import com.amazonaws.services.kms.AWSKMS;
import com.amazonaws.services.kms.AWSKMSClientBuilder;

import java.security.GeneralSecurityException;
import java.util.HashMap;
import java.util.Map;

public class EncryptionContextOverridesWithDynamoDBMapper {

    private static DynamoDBMapperConfig mapperConfig = DynamoDBMapperConfig.builder()
            .withSaveBehavior(DynamoDBMapperConfig.SaveBehavior.PUT).build();

    public static void main(String[] args) throws GeneralSecurityException {
        final String cmkArn = args[0];
        final String region = args[1];

        AmazonDynamoDB ddb = null;
        AWSKMS kms = null;
        try {
            ddb = AmazonDynamoDBClientBuilder.standard().withRegion(region).build();
            kms = AWSKMSClientBuilder.standard().withRegion(region).build();
            encryptRecord(cmkArn, ddb, kms);
        } finally {
            if (ddb != null) {
                ddb.shutdown();
            }
            if (kms != null) {
                kms.shutdown();
            }
        }
    }

    public static void encryptRecord(final String cmkArn,
                                     AmazonDynamoDB ddb,
                                     AWSKMS kms) throws GeneralSecurityException {
        final String dynamoTableName = "DuckTable";
        final String dynamoBackupName = "DuckBackup";

        DuckPojo duckPojo = new DuckPojo();
        duckPojo.setDuckName("Quackley");
        duckPojo.setSwimming(true);

        final DirectKmsMaterialProvider cmp = new DirectKmsMaterialProvider(kms, cmkArn);
        final DynamoDBEncryptor encryptor = DynamoDBEncryptor.getInstance(cmp);

        encryptor.setEncryptionContextOverrideOperator(EncryptionContextOperators.overrideEncryptionContextTableName(
                dynamoBackupName, dynamoTableName));
        // EncryptionContextOperators.overrideEncryptionContextTableNameUsingMap may also be used to create overrides
        // for several tables

        DynamoDBMapper mapper = new DynamoDBMapper(ddb, mapperConfig, new AttributeEncryptor(encryptor));

        // Encrypt and save the record to the DuckTable
        mapper.save(duckPojo);

        // Copy the encrypted record to the backup
        copyRecordsToBackup(ddb, dynamoTableName, dynamoBackupName);

        // Load and decrypt using the backup. Without using the override, decryption fails.
        mapper.load(duckPojo, DynamoDBMapperConfig.builder()
                .withTableNameOverride(DynamoDBMapperConfig.TableNameOverride.withTableNameReplacement(dynamoBackupName))
                .build());
    }

    public static void copyRecordsToBackup(AmazonDynamoDB dynamoDB, String mainTableName, String backupName) {
        Map<String, AttributeValue> key = new HashMap<>();
        key.put("duckName", new AttributeValue().withS("Quackley"));

        GetItemRequest getItemRequest = new GetItemRequest(mainTableName, key);
        GetItemResult item = dynamoDB.getItem(getItemRequest);

        PutItemRequest putItemRequest = new PutItemRequest();
        putItemRequest.withTableName(backupName);
        putItemRequest.withItem(item.getItem());
        dynamoDB.putItem(putItemRequest);
    }

    @DynamoDBTable(tableName = "DuckTable")
    public static final class DuckPojo {
        private String duckName;
        private boolean swimming;

        @DynamoDBHashKey(attributeName = "duckName")
        public String getDuckName() {
            return duckName;
        }

        public void setDuckName(String duckName) {
            this.duckName = duckName;
        }

        @DynamoDBAttribute
        public boolean isSwimming() {
            return swimming;
        }

        public void setSwimming(boolean swimming) {
            this.swimming = swimming;
        }

        public String toString() {
            return String.format("{duck_name: %s, swimming: %s}", duckName, swimming);
        }
    }

}
