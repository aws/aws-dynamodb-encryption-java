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

import com.amazonaws.services.dynamodbv2.datamodeling.DynamoDBMapper;
import com.amazonaws.services.dynamodbv2.datamodeling.DynamoDBMapperConfig;
import com.amazonaws.services.dynamodbv2.datamodeling.DynamoDBMapperConfig.ConsistentReads;
import com.amazonaws.services.dynamodbv2.datamodeling.DynamoDBQueryExpression;
import com.amazonaws.services.dynamodbv2.mapper.encryption.RangeKeyTestClass;
import com.amazonaws.services.dynamodbv2.mapper.encryption.TestDynamoDBMapperFactory;
import com.amazonaws.services.dynamodbv2.model.AttributeValue;
import com.amazonaws.services.dynamodbv2.model.ComparisonOperator;
import com.amazonaws.services.dynamodbv2.model.Condition;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.Random;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertTrue;
import static org.testng.Assert.fail;

/**
 * Integration tests for the query operation on DynamoDBMapper.
 */
public class QueryITCase extends DynamoDBMapperCryptoIntegrationTestBase {
    private static final boolean DEBUG = true;
    private static final long HASH_KEY = System.currentTimeMillis();
    private static RangeKeyTestClass hashKeyObject;
    private static final int TEST_ITEM_NUMBER = 500;
    private static DynamoDBMapper mapper;

    @BeforeClass
    public static void setUp() throws Exception {
        setUpTableWithRangeAttribute();

        DynamoDBMapperConfig mapperConfig = new DynamoDBMapperConfig(
                ConsistentReads.CONSISTENT);
        mapper = TestDynamoDBMapperFactory.createDynamoDBMapper(dynamo, mapperConfig);

        putTestData(mapper, TEST_ITEM_NUMBER);

        hashKeyObject = new RangeKeyTestClass();
        hashKeyObject.setKey(HASH_KEY);
    }

    @Test
    public void testQueryWithPrimaryRangeKey() throws Exception {
        DynamoDBQueryExpression<RangeKeyTestClass> queryExpression = new DynamoDBQueryExpression<RangeKeyTestClass>()
                .withHashKeyValues(hashKeyObject)
                .withRangeKeyCondition(
                        "rangeKey",
                        new Condition().withComparisonOperator(
                                ComparisonOperator.GT).withAttributeValueList(
                                new AttributeValue().withN("1.0")))
                .withLimit(11);
        List<RangeKeyTestClass> list = mapper.query(RangeKeyTestClass.class,
                queryExpression);

        int count = 0;
        Iterator<RangeKeyTestClass> iterator = list.iterator();
        while (iterator.hasNext()) {
            count++;
            RangeKeyTestClass next = iterator.next();
            assertTrue(next.getRangeKey() > 1.00);
        }

        int numMatchingObjects = TEST_ITEM_NUMBER - 2;
        if (DEBUG)
            System.err.println("count=" + count + ", numMatchingObjects=" + numMatchingObjects);
        assertTrue(count == numMatchingObjects);
        assertTrue(numMatchingObjects == list.size());

        assertNotNull(list.get(list.size() / 2));
        assertTrue(list.contains(list.get(list.size() / 2)));
        assertTrue(numMatchingObjects == list.toArray().length);

        Thread.sleep(250);
        int totalCount = mapper.count(RangeKeyTestClass.class, queryExpression);
        assertTrue(numMatchingObjects == totalCount);

        /**
         * Tests query with only hash key
         */
        queryExpression = new DynamoDBQueryExpression<RangeKeyTestClass>()
                .withHashKeyValues(hashKeyObject);
        list = mapper.query(RangeKeyTestClass.class, queryExpression);
        assertTrue(TEST_ITEM_NUMBER ==  list.size());
    }

    /**
     * Tests making queries using query filter on non-key attributes.
     */
    @Test
    public void testQueryFilter() {
        // A random filter condition to be applied to the query.
        Random random = new Random();
        int randomFilterValue = random.nextInt(TEST_ITEM_NUMBER);
        Condition filterCondition = new Condition().withComparisonOperator(
                ComparisonOperator.LT)
                .withAttributeValueList(
                        new AttributeValue().withN(Integer.toString(randomFilterValue)));

        /*
         * (1) Apply the filter on the range key, in form of key condition
         */
        DynamoDBQueryExpression<RangeKeyTestClass> queryWithRangeKeyCondition = 
                new DynamoDBQueryExpression<RangeKeyTestClass>()
                .withHashKeyValues(hashKeyObject).withRangeKeyCondition(
                        "rangeKey", filterCondition);
        List<RangeKeyTestClass> rangeKeyConditionResult = mapper.query(
                RangeKeyTestClass.class, queryWithRangeKeyCondition);

        /*
         * (2) Apply the filter on the bigDecimalAttribute, in form of query
         * filter
         */
        DynamoDBQueryExpression<RangeKeyTestClass> queryWithQueryFilterCondition =
                new DynamoDBQueryExpression<RangeKeyTestClass>()
                .withHashKeyValues(hashKeyObject).withQueryFilter(
                        Collections.singletonMap("bigDecimalAttribute",
                                filterCondition));
        List<RangeKeyTestClass> queryFilterResult = mapper.query(
                RangeKeyTestClass.class, queryWithQueryFilterCondition);
        if (DEBUG) {
            System.err.println("rangeKeyConditionResult.size()="
                    + rangeKeyConditionResult.size()
                    + ", queryFilterResult.size()=" + queryFilterResult.size());
        }
        assertTrue(rangeKeyConditionResult.size() == queryFilterResult.size());
        for (int i = 0; i < rangeKeyConditionResult.size(); i++) {
            assertEquals(rangeKeyConditionResult.get(i),
                    queryFilterResult.get(i));
        }
    }

    /**
     * Tests that exception should be raised when user provides an index name
     * when making query with the primary range key.
     */
    @Test
    public void testUnnecessaryIndexNameException() {
        try {
            DynamoDBMapper mapper = TestDynamoDBMapperFactory
                    .createDynamoDBMapper(dynamo);
            long hashKey = System.currentTimeMillis();
            RangeKeyTestClass keyObject = new RangeKeyTestClass();
            keyObject.setKey(hashKey);
            DynamoDBQueryExpression<RangeKeyTestClass> queryExpression = new DynamoDBQueryExpression<RangeKeyTestClass>()
                    .withHashKeyValues(keyObject);
            queryExpression
                    .withRangeKeyCondition(
                            "rangeKey",
                            new Condition().withComparisonOperator(
                                    ComparisonOperator.GT.toString())
                                    .withAttributeValueList(
                                            new AttributeValue().withN("1.0")))
                    .withLimit(11).withIndexName("some_index");
            mapper.query(RangeKeyTestClass.class, queryExpression);
            fail("User should not provide index name when making query with the primary range key");
        } catch (IllegalArgumentException expected) {
            System.out.println(expected.getMessage());
        } catch (Exception e) {
            fail("Should trigger AmazonClientException.");
        }

    }

    /**
     * Use BatchSave to put some test data into the tested table. Each item is
     * hash-keyed by the same value, and range-keyed by numbers starting from 0.
     */
    private static void putTestData(DynamoDBMapper mapper, int itemNumber) {
        List<RangeKeyTestClass> objs = new ArrayList<RangeKeyTestClass>();
        for (int i = 0; i < itemNumber; i++) {
            RangeKeyTestClass obj = new RangeKeyTestClass();
            obj.setKey(HASH_KEY);
            obj.setRangeKey(i);
            obj.setBigDecimalAttribute(new BigDecimal(i));
            objs.add(obj);
        }
        mapper.batchSave(objs);
    }
}
