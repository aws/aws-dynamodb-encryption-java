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

import com.amazonaws.services.dynamodbv2.datamodeling.DynamoDBHashKey;
import com.amazonaws.services.dynamodbv2.datamodeling.DynamoDBIndexHashKey;
import com.amazonaws.services.dynamodbv2.datamodeling.DynamoDBIndexRangeKey;
import com.amazonaws.services.dynamodbv2.datamodeling.DynamoDBMapper;
import com.amazonaws.services.dynamodbv2.datamodeling.DynamoDBQueryExpression;
import com.amazonaws.services.dynamodbv2.datamodeling.DynamoDBTable;
import com.amazonaws.services.dynamodbv2.datamodeling.PaginatedQueryList;
import com.amazonaws.services.dynamodbv2.datamodeling.encryption.DoNotEncrypt;
import com.amazonaws.services.dynamodbv2.mapper.encryption.TestDynamoDBMapperFactory;
import com.amazonaws.services.dynamodbv2.model.AttributeDefinition;
import com.amazonaws.services.dynamodbv2.model.AttributeValue;
import com.amazonaws.services.dynamodbv2.model.ComparisonOperator;
import com.amazonaws.services.dynamodbv2.model.Condition;
import com.amazonaws.services.dynamodbv2.model.CreateTableRequest;
import com.amazonaws.services.dynamodbv2.model.GlobalSecondaryIndex;
import com.amazonaws.services.dynamodbv2.model.KeySchemaElement;
import com.amazonaws.services.dynamodbv2.model.KeyType;
import com.amazonaws.services.dynamodbv2.model.Projection;
import com.amazonaws.services.dynamodbv2.model.ProjectionType;
import com.amazonaws.services.dynamodbv2.model.ProvisionedThroughput;
import com.amazonaws.services.dynamodbv2.model.ScalarAttributeType;
import com.amazonaws.services.dynamodbv2.util.TableUtils;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import java.util.ArrayList;
import java.util.List;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertTrue;


/**
 * Integration test for GSI support with a table that has no primary range key
 * (only a primary hash key).
 */
public class HashKeyOnlyTableWithGSIITCase extends
        DynamoDBMapperCryptoIntegrationTestBase {

    public static final String HASH_KEY_ONLY_TABLE_NAME = "no-primary-range-key-gsi-test-crypto";

    @BeforeClass
    public static void setUp() throws Exception {
        DynamoDBTestBase.setUpTestBase();
        List<KeySchemaElement> keySchema = new ArrayList<KeySchemaElement>();
        keySchema.add(new KeySchemaElement("id", KeyType.HASH));

        CreateTableRequest req = new CreateTableRequest(
                HASH_KEY_ONLY_TABLE_NAME, keySchema)
                .withProvisionedThroughput(new ProvisionedThroughput(10L, 10L))
                .withAttributeDefinitions(
                        new AttributeDefinition("id", ScalarAttributeType.S),
                        new AttributeDefinition("status", ScalarAttributeType.S),
                        new AttributeDefinition("ts", ScalarAttributeType.S))
                .withGlobalSecondaryIndexes(
                        new GlobalSecondaryIndex()
                                .withProvisionedThroughput(
                                        new ProvisionedThroughput(10L, 10L))
                                .withIndexName("statusAndCreation")
                                .withKeySchema(
                                        new KeySchemaElement("status",
                                                KeyType.HASH),
                                        new KeySchemaElement("ts",
                                                KeyType.RANGE))
                                .withProjection(
                                        new Projection()
                                                .withProjectionType(ProjectionType.ALL)));

        TableUtils.createTableIfNotExists(dynamo, req);
        TableUtils.waitUntilActive(dynamo, HASH_KEY_ONLY_TABLE_NAME);
    }

    @AfterClass
    public static void tearDown() throws Exception {
        dynamo.deleteTable(HASH_KEY_ONLY_TABLE_NAME);
    }

    @DynamoDBTable(tableName = HASH_KEY_ONLY_TABLE_NAME)
    public static class User {
        private String id;
        private String status;
        private String ts;

        @DynamoDBHashKey
        public String getId() {
            return id;
        }

        public void setId(String id) {
            this.id = id;
        }

        @DoNotEncrypt
        @DynamoDBIndexHashKey(globalSecondaryIndexName = "statusAndCreation")
        public String getStatus() {
            return status;
        }

        public void setStatus(String status) {
            this.status = status;
        }

        @DoNotEncrypt
        @DynamoDBIndexRangeKey(globalSecondaryIndexName = "statusAndCreation")
        public String getTs() {
            return ts;
        }

        public void setTs(String ts) {
            this.ts = ts;
        }
    }

    /**
     * Tests that we can query using the hash/range GSI on our hash-key only
     * table.
     */
    @Test
    public void testGSIQuery() throws Exception {
        DynamoDBMapper mapper = TestDynamoDBMapperFactory
                .createDynamoDBMapper(dynamo);
        String status = "foo-status";

        User user = new User();
        user.setId("123");
        user.setStatus(status);
        user.setTs("321");
        mapper.save(user);

        DynamoDBQueryExpression<User> expr = new DynamoDBQueryExpression<User>()
                .withIndexName("statusAndCreation")
                .withLimit(100)
                .withConsistentRead(false)
                .withHashKeyValues(user)
                .withRangeKeyCondition(
                        "ts",
                        new Condition()
                        .withComparisonOperator(ComparisonOperator.GT)
                        .withAttributeValueList(new AttributeValue("100")));

        PaginatedQueryList<User> query = mapper.query(User.class, expr);
        int size = query.size();
        if (DEBUG)
            System.err.println("size=" + size);
        assertTrue(1 == size);
        assertEquals(status, query.get(0).getStatus());
    }
    private static final boolean DEBUG = false;
}
