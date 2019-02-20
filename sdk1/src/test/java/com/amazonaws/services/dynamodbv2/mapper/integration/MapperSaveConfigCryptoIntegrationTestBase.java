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

import com.amazonaws.services.dynamodbv2.datamodeling.DynamoDBAttribute;
import com.amazonaws.services.dynamodbv2.datamodeling.DynamoDBHashKey;
import com.amazonaws.services.dynamodbv2.datamodeling.DynamoDBMapper;
import com.amazonaws.services.dynamodbv2.datamodeling.DynamoDBMapperConfig;
import com.amazonaws.services.dynamodbv2.datamodeling.DynamoDBMapperConfig.SaveBehavior;
import com.amazonaws.services.dynamodbv2.datamodeling.DynamoDBRangeKey;
import com.amazonaws.services.dynamodbv2.datamodeling.DynamoDBTable;
import com.amazonaws.services.dynamodbv2.datamodeling.encryption.DoNotTouch;
import com.amazonaws.services.dynamodbv2.mapper.encryption.TestDynamoDBMapperFactory;
import com.amazonaws.services.dynamodbv2.model.AttributeDefinition;
import com.amazonaws.services.dynamodbv2.model.CreateTableRequest;
import com.amazonaws.services.dynamodbv2.model.KeySchemaElement;
import com.amazonaws.services.dynamodbv2.model.KeyType;
import com.amazonaws.services.dynamodbv2.model.ProvisionedThroughput;
import com.amazonaws.services.dynamodbv2.model.ScalarAttributeType;
import com.amazonaws.services.dynamodbv2.model.TableDescription;
import com.amazonaws.services.dynamodbv2.util.TableUtils;
import org.testng.annotations.BeforeClass;

import java.util.Set;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;


public class MapperSaveConfigCryptoIntegrationTestBase extends DynamoDBCryptoIntegrationTestBase {

    protected static DynamoDBMapper dynamoMapper;

    protected static final DynamoDBMapperConfig defaultConfig = new DynamoDBMapperConfig(
            SaveBehavior.UPDATE);
    protected static final DynamoDBMapperConfig updateSkipNullConfig = new DynamoDBMapperConfig(
            SaveBehavior.UPDATE_SKIP_NULL_ATTRIBUTES);
    protected static final DynamoDBMapperConfig appendSetConfig = new DynamoDBMapperConfig(
            SaveBehavior.APPEND_SET);
    protected static final DynamoDBMapperConfig clobberConfig = new DynamoDBMapperConfig(
            SaveBehavior.CLOBBER);

    protected static final String tableName = "aws-java-sdk-dynamodb-mapper-save-config-test-crypto";

    protected static final String hashKeyName = "hashKey";

    protected static final String rangeKeyName = "rangeKey";

    protected static final String nonKeyAttributeName = "nonKeyAttribute";

    protected static final String stringSetAttributeName = "stringSetAttribute";

    /** Read capacity for the test table being created in Amazon DynamoDB. */
    protected static final Long READ_CAPACITY = 10L;

    /** Write capacity for the test table being created in Amazon DynamoDB. */
    protected static final Long WRITE_CAPACITY = 5L;

    /** Provisioned Throughput for the test table created in Amazon DynamoDB */
    protected static final ProvisionedThroughput DEFAULT_PROVISIONED_THROUGHPUT = new ProvisionedThroughput()
            .withReadCapacityUnits(READ_CAPACITY).withWriteCapacityUnits(
                    WRITE_CAPACITY);

    @BeforeClass
    public static void setUp() throws Exception {
        DynamoDBCryptoIntegrationTestBase.setUp();
        dynamoMapper = TestDynamoDBMapperFactory.createDynamoDBMapper(dynamo);

        CreateTableRequest createTableRequest = new CreateTableRequest()
                .withTableName(tableName)
                .withKeySchema(new KeySchemaElement().withAttributeName(hashKeyName).withKeyType(KeyType.HASH))
                .withKeySchema(new KeySchemaElement().withAttributeName(rangeKeyName).withKeyType(KeyType.RANGE))
                .withAttributeDefinitions(new AttributeDefinition().withAttributeName(hashKeyName)
                        .withAttributeType(ScalarAttributeType.S))
                .withAttributeDefinitions(new AttributeDefinition().withAttributeName(rangeKeyName)
                        .withAttributeType(ScalarAttributeType.N));
        createTableRequest.setProvisionedThroughput(DEFAULT_PROVISIONED_THROUGHPUT);

        if (TableUtils.createTableIfNotExists(dynamo, createTableRequest)) {
            TableUtils.waitUntilActive(dynamo, tableName);
        }
    }

    @DynamoDBTable(tableName = tableName)
    static public class TestItem {

        private String hashKey;
        private Long rangeKey;
        private String nonKeyAttribute;
        private Set<String> stringSetAttribute;

        @DynamoDBHashKey(attributeName = hashKeyName)
        public String getHashKey() {
            return hashKey;
        }

        public void setHashKey(String hashKey) {
            this.hashKey = hashKey;
        }

        @DynamoDBRangeKey(attributeName = rangeKeyName)
        public Long getRangeKey() {
            return rangeKey;
        }

        public void setRangeKey(Long rangeKey) {
            this.rangeKey = rangeKey;
        }

        @DoNotTouch
        @DynamoDBAttribute(attributeName = nonKeyAttributeName)
        public String getNonKeyAttribute() {
            return nonKeyAttribute;
        }

        public void setNonKeyAttribute(String nonKeyAttribute) {
            this.nonKeyAttribute = nonKeyAttribute;
        }

        @DoNotTouch
        @DynamoDBAttribute(attributeName = stringSetAttributeName)
        public Set<String> getStringSetAttribute() {
            return stringSetAttribute;
        }

        public void setStringSetAttribute(Set<String> stringSetAttribute) {
            this.stringSetAttribute = stringSetAttribute;
        }

    }

    @DynamoDBTable(tableName = tableName)
    static public class TestAppendToScalarItem {

        private String hashKey;
        private Long rangeKey;
        private Set<String> fakeStringSetAttribute;

        @DynamoDBHashKey(attributeName = hashKeyName)
        public String getHashKey() {
            return hashKey;
        }

        public void setHashKey(String hashKey) {
            this.hashKey = hashKey;
        }

        @DynamoDBRangeKey(attributeName = rangeKeyName)
        public Long getRangeKey() {
            return rangeKey;
        }

        public void setRangeKey(Long rangeKey) {
            this.rangeKey = rangeKey;
        }

        @DynamoDBAttribute(attributeName = nonKeyAttributeName)
        public Set<String> getFakeStringSetAttribute() {
            return fakeStringSetAttribute;
        }

        public void setFakeStringSetAttribute(Set<String> stringSetAttribute) {
            this.fakeStringSetAttribute = stringSetAttribute;
        }
    }

    /**
     * Helper method to create a table in Amazon DynamoDB
     */
    protected static void createTestTable(
            ProvisionedThroughput provisionedThroughput) {
        CreateTableRequest createTableRequest = new CreateTableRequest()
                .withTableName(tableName)
                .withKeySchema(
                        new KeySchemaElement().withAttributeName(
                                hashKeyName).withKeyType(
                                KeyType.HASH))
                .withKeySchema(
                        new KeySchemaElement().withAttributeName(
                                rangeKeyName).withKeyType(
                                KeyType.RANGE))
                .withAttributeDefinitions(
                        new AttributeDefinition().withAttributeName(
                                hashKeyName).withAttributeType(
                                ScalarAttributeType.S))
                .withAttributeDefinitions(
                        new AttributeDefinition().withAttributeName(
                                rangeKeyName).withAttributeType(
                                ScalarAttributeType.N));
        createTableRequest.setProvisionedThroughput(provisionedThroughput);

        TableDescription createdTableDescription = dynamo.createTable(
                createTableRequest).getTableDescription();
        System.out.println("Created Table: " + createdTableDescription);
        assertEquals(tableName, createdTableDescription.getTableName());
        assertNotNull(createdTableDescription.getTableStatus());
        assertEquals(hashKeyName, createdTableDescription
                .getKeySchema().get(0).getAttributeName());
        assertEquals(KeyType.HASH.toString(), createdTableDescription
                .getKeySchema().get(0).getKeyType());
        assertEquals(rangeKeyName, createdTableDescription
                .getKeySchema().get(1).getAttributeName());
        assertEquals(KeyType.RANGE.toString(), createdTableDescription
                .getKeySchema().get(1).getKeyType());
    }
}
