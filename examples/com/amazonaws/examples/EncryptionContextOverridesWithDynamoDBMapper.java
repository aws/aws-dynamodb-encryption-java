package com.amazonaws.examples;

import com.amazonaws.services.dynamodbv2.AmazonDynamoDB;
import com.amazonaws.services.dynamodbv2.AmazonDynamoDBClientBuilder;
import com.amazonaws.services.dynamodbv2.datamodeling.AttributeEncryptor;
import com.amazonaws.services.dynamodbv2.datamodeling.DynamoDBAttribute;
import com.amazonaws.services.dynamodbv2.datamodeling.DynamoDBHashKey;
import com.amazonaws.services.dynamodbv2.datamodeling.DynamoDBMapper;
import com.amazonaws.services.dynamodbv2.datamodeling.DynamoDBMapperConfig;
import com.amazonaws.services.dynamodbv2.datamodeling.DynamoDBRangeKey;
import com.amazonaws.services.dynamodbv2.datamodeling.DynamoDBTable;
import com.amazonaws.services.dynamodbv2.datamodeling.encryption.DynamoDBEncryptor;
import com.amazonaws.services.dynamodbv2.datamodeling.encryption.providers.DirectKmsMaterialProvider;
import com.amazonaws.services.dynamodbv2.model.AttributeValue;
import com.amazonaws.services.kms.AWSKMS;
import com.amazonaws.services.kms.AWSKMSClientBuilder;

import java.security.GeneralSecurityException;
import java.util.HashMap;
import java.util.Map;

import static com.amazonaws.services.dynamodbv2.datamodeling.encryption.utils.EncryptionContextOperators.overrideEncryptionContextTableNameUsingMap;

public class EncryptionContextOverridesWithDynamoDBMapper {
    public static void main(String[] args) throws GeneralSecurityException {
        final String cmkArn = args[0];
        final String region = args[1];
        final String encryptionContextTableName = args[2];

        encryptRecord(cmkArn, region, encryptionContextTableName);
    }

    public static void encryptRecord(final String cmkArn,
                                     final String region,
                                     final String newEncryptionContextTableName) {
        // Sample object to be encrypted
        ExampleItem record = new ExampleItem();
        record.setPartitionAttribute("is this");
        record.setSortAttribute(55);
        record.setExample("my data");

        // Set up our configuration and clients
        final AmazonDynamoDB ddb = AmazonDynamoDBClientBuilder.standard().withRegion(region).build();
        final AWSKMS kms = AWSKMSClientBuilder.standard().withRegion(region).build();
        final DirectKmsMaterialProvider cmp = new DirectKmsMaterialProvider(kms, cmkArn);
        // Encryptor creation
        final DynamoDBEncryptor encryptor = DynamoDBEncryptor.getInstance(cmp);

        Map<String, String> tableNameEncryptionContextOverrides = new HashMap<>();
        tableNameEncryptionContextOverrides.put("ExampleTableForEncryptionContextOverrides", newEncryptionContextTableName);
        tableNameEncryptionContextOverrides.put("AnotherExampleTableForEncryptionContextOverrides", "this table doesn't exist");

        // Here we supply an operator to override the table name used in the encryption context
        encryptor.setEncryptionContextOverrideOperator(
                overrideEncryptionContextTableNameUsingMap(tableNameEncryptionContextOverrides)
        );

        // Mapper Creation
        // Please note the use of SaveBehavior.CLOBBER (SaveBehavior.PUT works as well).
        // Omitting this can result in data-corruption.
        DynamoDBMapperConfig mapperConfig = DynamoDBMapperConfig.builder()
                .withSaveBehavior(DynamoDBMapperConfig.SaveBehavior.CLOBBER).build();
        DynamoDBMapper mapper = new DynamoDBMapper(ddb, mapperConfig, new AttributeEncryptor(encryptor));

        System.out.println("Plaintext Record: " + record);
        // Save the record to the DynamoDB table
        mapper.save(record);

        // Retrieve the encrypted record (directly without decrypting) from Dynamo so we can see it in our example
        final Map<String, AttributeValue> itemKey = new HashMap<>();
        itemKey.put("partition_attribute", new AttributeValue().withS("is this"));
        itemKey.put("sort_attribute", new AttributeValue().withN("55"));
        System.out.println("Encrypted Record: " + ddb.getItem("ExampleTableForEncryptionContextOverrides",
                itemKey).getItem());

        // Retrieve (and decrypt) it from DynamoDB
        ExampleItem decrypted_record = mapper.load(ExampleItem.class, "is this", 55);
        System.out.println("Decrypted Record: " + decrypted_record);
    }

    @DynamoDBTable(tableName = "ExampleTableForEncryptionContextOverrides")
    public static final class ExampleItem {
        private String partitionAttribute;
        private int sortAttribute;
        private String example;

        @DynamoDBHashKey(attributeName = "partition_attribute")
        public String getPartitionAttribute() {
            return partitionAttribute;
        }

        public void setPartitionAttribute(String partitionAttribute) {
            this.partitionAttribute = partitionAttribute;
        }

        @DynamoDBRangeKey(attributeName = "sort_attribute")
        public int getSortAttribute() {
            return sortAttribute;
        }

        public void setSortAttribute(int sortAttribute) {
            this.sortAttribute = sortAttribute;
        }

        @DynamoDBAttribute(attributeName = "example")
        public String getExample() {
            return example;
        }

        public void setExample(String example) {
            this.example = example;
        }
    }

}
