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
import com.amazonaws.services.dynamodbv2.datamodeling.DynamoDBMapper.FailedBatch;
import com.amazonaws.services.dynamodbv2.mapper.encryption.BinaryAttributeByteBufferTestClass;
import com.amazonaws.services.dynamodbv2.mapper.encryption.NoSuchTableTestClass;
import com.amazonaws.services.dynamodbv2.mapper.encryption.NumberSetAttributeTestClass;
import com.amazonaws.services.dynamodbv2.mapper.encryption.RangeKeyTestClass;
import com.amazonaws.services.dynamodbv2.mapper.encryption.TestDynamoDBMapperFactory;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Collections;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertTrue;
import static org.testng.Assert.fail;

/**
 * Tests batch write calls
 */
public class BatchWriteITCase extends DynamoDBMapperCryptoIntegrationTestBase {

    // We don't start with the current system millis like other tests because
    // it's out of the range of some data types
    private static int start = 1;
    private static int byteStart = 1;
    private static int startKeyDebug = 1;

    @BeforeClass
    public static void setUp() throws Exception {
    	setUpTableWithRangeAttribute();
    }

    @Test
    public void testBatchSave() throws Exception {
        List<NumberSetAttributeTestClass> objs = new ArrayList<NumberSetAttributeTestClass>();
        for ( int i = 0; i < 40; i++ ) {
            NumberSetAttributeTestClass obj = getUniqueNumericObject();
            objs.add(obj);
        }

        DynamoDBMapper mapper = TestDynamoDBMapperFactory.createDynamoDBMapper(dynamo);
        List<FailedBatch> failedBatches = mapper.batchSave(objs);

        assertTrue(0 == failedBatches.size());

        for (NumberSetAttributeTestClass obj : objs) {
            NumberSetAttributeTestClass loaded = mapper.load(NumberSetAttributeTestClass.class, obj.getKey());
            assertEquals(obj, loaded);
        }
    }

    @Test
    public void testBatchSaveAsArray() throws Exception {
        List<NumberSetAttributeTestClass> objs = new ArrayList<NumberSetAttributeTestClass>();
        for ( int i = 0; i < 40; i++ ) {
            NumberSetAttributeTestClass obj = getUniqueNumericObject();
            objs.add(obj);
        }

        DynamoDBMapper mapper = TestDynamoDBMapperFactory.createDynamoDBMapper(dynamo);
        NumberSetAttributeTestClass[] objsArray = objs.toArray(new NumberSetAttributeTestClass[objs.size()]);
        mapper.batchSave((Object[])objsArray);

        for (NumberSetAttributeTestClass obj : objs) {
            NumberSetAttributeTestClass loaded = mapper.load(NumberSetAttributeTestClass.class, obj.getKey());
            assertEquals(obj, loaded);
        }
    }

    @Test
    public void testBatchSaveAsListFromArray() throws Exception {
        List<NumberSetAttributeTestClass> objs = new ArrayList<NumberSetAttributeTestClass>();
        for ( int i = 0; i < 40; i++ ) {
            NumberSetAttributeTestClass obj = getUniqueNumericObject();
            objs.add(obj);
        }

        DynamoDBMapper mapper = TestDynamoDBMapperFactory.createDynamoDBMapper(dynamo);
        NumberSetAttributeTestClass[] objsArray = objs.toArray(new NumberSetAttributeTestClass[objs.size()]);
        mapper.batchSave(Arrays.asList(objsArray));

        for (NumberSetAttributeTestClass obj : objs) {
            NumberSetAttributeTestClass loaded = mapper.load(NumberSetAttributeTestClass.class, obj.getKey());
            assertEquals(obj, loaded);
        }
    }

    @Test
    public void testBatchDelete() throws Exception {
        List<NumberSetAttributeTestClass> objs = new ArrayList<NumberSetAttributeTestClass>();
        for ( int i = 0; i < 40; i++ ) {
            NumberSetAttributeTestClass obj = getUniqueNumericObject();
            objs.add(obj);
        }

        DynamoDBMapper mapper = TestDynamoDBMapperFactory.createDynamoDBMapper(dynamo);
        mapper.batchSave(objs);

        for ( NumberSetAttributeTestClass obj : objs ) {
            NumberSetAttributeTestClass loaded = mapper.load(NumberSetAttributeTestClass.class, obj.getKey());
            assertEquals(obj, loaded);
        }

        // Delete the odd ones
        int i = 0;
        List<NumberSetAttributeTestClass> toDelete = new LinkedList<NumberSetAttributeTestClass>();
        for ( NumberSetAttributeTestClass obj : objs ) {
            if (i++ % 2 == 0) toDelete.add(obj);
        }

        mapper.batchDelete(toDelete);

        i = 0;
        for ( NumberSetAttributeTestClass obj : objs ) {
            NumberSetAttributeTestClass loaded = mapper.load(NumberSetAttributeTestClass.class, obj.getKey());
            if (i++ % 2 == 0) {
                assertNull(loaded);
            } else {
                assertEquals(obj, loaded);
            }
        }
    }

    @Test
    public void testBatchSaveAndDelete() throws Exception {
        List<NumberSetAttributeTestClass> objs = new ArrayList<NumberSetAttributeTestClass>();
        for ( int i = 0; i < 40; i++ ) {
            NumberSetAttributeTestClass obj = getUniqueNumericObject();
            objs.add(obj);
        }

        DynamoDBMapper mapper = TestDynamoDBMapperFactory.createDynamoDBMapper(dynamo);
        mapper.batchSave(objs);

        for ( NumberSetAttributeTestClass obj : objs ) {
            NumberSetAttributeTestClass loaded = mapper.load(NumberSetAttributeTestClass.class, obj.getKey());
            assertEquals(obj, loaded);
        }

        // Delete the odd ones
        int i = 0;
        List<NumberSetAttributeTestClass> toDelete = new LinkedList<NumberSetAttributeTestClass>();
        for ( NumberSetAttributeTestClass obj : objs ) {
            if (i++ % 2 == 0) toDelete.add(obj);
        }

        // And add a bunch of new ones
        List<NumberSetAttributeTestClass> toSave = new LinkedList<NumberSetAttributeTestClass>();
        for ( i = 0; i < 50; i++ ) {
            NumberSetAttributeTestClass obj = getUniqueNumericObject();
            toSave.add(obj);
        }

        mapper.batchWrite(toSave, toDelete);

        i = 0;
        for ( NumberSetAttributeTestClass obj : objs ) {
            NumberSetAttributeTestClass loaded = mapper.load(NumberSetAttributeTestClass.class, obj.getKey());
            if (i++ % 2 == 0) {
                assertNull(loaded);
            } else {
                assertEquals(obj, loaded);
            }
        }

        for ( NumberSetAttributeTestClass obj : toSave ) {
            NumberSetAttributeTestClass loaded = mapper.load(NumberSetAttributeTestClass.class, obj.getKey());
            assertEquals(obj, loaded);
        }
    }

    @Test
    public void testMultipleTables() throws Exception {

        List<Object> objs = new ArrayList<Object>();
        int numItems = 10;
        for ( int i = 0; i < numItems; i++ ) {
            NumberSetAttributeTestClass obj = getUniqueNumericObject();
            objs.add(obj);
        }
        for ( int i = 0; i < numItems; i++ ) {
            RangeKeyTestClass obj = getUniqueRangeKeyObject();
            objs.add(obj);
        }
        Collections.shuffle(objs);

        DynamoDBMapper mapper = TestDynamoDBMapperFactory.createDynamoDBMapper(dynamo);
        List<FailedBatch> failedBatches = mapper.batchSave(objs);
        assertTrue(failedBatches.size() == 0);

        for ( Object obj : objs ) {
            Object loaded = null;
            if ( obj instanceof NumberSetAttributeTestClass ) {
                loaded = mapper.load(NumberSetAttributeTestClass.class, ((NumberSetAttributeTestClass) obj).getKey());
            } else if ( obj instanceof RangeKeyTestClass ) {
                loaded = mapper.load(RangeKeyTestClass.class, ((RangeKeyTestClass) obj).getKey(),
                        ((RangeKeyTestClass) obj).getRangeKey());
            } else {
                fail();
            }
            assertEquals(obj, loaded);
        }

        // Delete the odd ones
        int i = 0;
        List<Object> toDelete = new LinkedList<Object>();
        for ( Object obj : objs ) {
            if (i++ % 2 == 0) toDelete.add(obj);
        }

        // And add a bunch of new ones
        List<Object> toSave = new LinkedList<Object>();
        for ( i = 0; i < numItems; i++ ) {
            if ( i % 2 == 0 )
                toSave.add(getUniqueNumericObject());
            else
                toSave.add(getUniqueRangeKeyObject());
        }

        failedBatches = mapper.batchWrite(toSave, toDelete);
        assertTrue(0 == failedBatches.size());

        i = 0;
        for ( Object obj : objs ) {
            Object loaded = null;
            if ( obj instanceof NumberSetAttributeTestClass ) {
                loaded = mapper.load(NumberSetAttributeTestClass.class, ((NumberSetAttributeTestClass) obj).getKey());
            } else if ( obj instanceof RangeKeyTestClass ) {
                loaded = mapper.load(RangeKeyTestClass.class, ((RangeKeyTestClass) obj).getKey(),
                        ((RangeKeyTestClass) obj).getRangeKey());
            } else {
                fail();
            }

            if (i++ % 2 == 0) {
                assertNull(loaded);
            } else {
                assertEquals(obj, loaded);
            }
        }

        for ( Object obj : toSave ) {
            Object loaded = null;
            if ( obj instanceof NumberSetAttributeTestClass ) {
                loaded = mapper.load(NumberSetAttributeTestClass.class, ((NumberSetAttributeTestClass) obj).getKey());
            } else if ( obj instanceof RangeKeyTestClass ) {
                loaded = mapper.load(RangeKeyTestClass.class, ((RangeKeyTestClass) obj).getKey(),
                        ((RangeKeyTestClass) obj).getRangeKey());
            } else {
                fail();
            }
            assertEquals(obj, loaded);
        }
    }

    /**
     * Test whether it finish processing all the items even if the first batch is failed.
     */
    @Test
    public void testErrorHandling() {

        List<Object> objs = new ArrayList<Object>();
        int numItems = 25;

        for (int i = 0; i < numItems; i++) {
            NoSuchTableTestClass obj = getuniqueBadObject();
            objs.add(obj);
        }

        for (int i = 0; i < numItems; i++) {
            RangeKeyTestClass obj = getUniqueRangeKeyObject();
            objs.add(obj);
        }

        DynamoDBMapper mapper = TestDynamoDBMapperFactory.createDynamoDBMapper(dynamo);

        // The failed batch
        List<FailedBatch> failedBatches = mapper.batchSave(objs);
        assertTrue(1 == failedBatches.size());
        assertTrue(numItems == failedBatches.get(0).getUnprocessedItems().get("tableNotExist").size());

        // The second batch succeeds, get them back
        for (Object obj : objs.subList(25, 50)) {
            RangeKeyTestClass loaded = mapper.load(RangeKeyTestClass.class, ((RangeKeyTestClass) obj).getKey(), ((RangeKeyTestClass) obj).getRangeKey());
            assertEquals(obj, loaded);
        }
    }

    /**
     * Test whether we can split large batch request into small pieces.
     */
    @Test
    public void testLargeRequestEntity() {

        // The total batch size is beyond 1M, test whether our client can split
        // the batch correctly
        List<BinaryAttributeByteBufferTestClass> objs = new ArrayList<BinaryAttributeByteBufferTestClass>();

        int numItems = 25;
        final int CONTENT_LENGTH = 1024 * 25;

        for (int i = 0; i < numItems; i++) {
            BinaryAttributeByteBufferTestClass obj = getUniqueByteBufferObject(CONTENT_LENGTH);
            objs.add(obj);
        }

        DynamoDBMapper mapper = TestDynamoDBMapperFactory.createDynamoDBMapper(dynamo);
        List<FailedBatch> failedBatches = mapper.batchSave(objs);
        assertEquals(failedBatches.size(), 0);

        // Get these objects back
        for (BinaryAttributeByteBufferTestClass obj : objs) {
            BinaryAttributeByteBufferTestClass loaded = mapper.load(BinaryAttributeByteBufferTestClass.class, obj.getKey());
            assertEquals(obj, loaded);
        }

        // There are three super large item together with some small ones, test
        // whether we can successfully
        // save these small items.
        objs.clear();
        numItems = 10;
        List<BinaryAttributeByteBufferTestClass> largeObjs = new ArrayList<BinaryAttributeByteBufferTestClass>();

        // Put three super large item(beyond 64k)
        largeObjs.add(getUniqueByteBufferObject(CONTENT_LENGTH * 30));
        largeObjs.add(getUniqueByteBufferObject(CONTENT_LENGTH * 30));
        largeObjs.add(getUniqueByteBufferObject(CONTENT_LENGTH * 30));
        for (int i = 0; i < numItems - 3; i++) {
            BinaryAttributeByteBufferTestClass obj = getUniqueByteBufferObject(CONTENT_LENGTH / 25);
            objs.add(obj);
        }

        objs.addAll(largeObjs);

        failedBatches = mapper.batchSave(objs);
        final int size = failedBatches.size();
        if (DEBUG)
            System.err.println("failedBatches.size()=" + size);
        assertThat(size, equalTo(1));
        objs.removeAll(largeObjs);
        mapper.batchSave(objs);

        // Get these small objects back
        for (BinaryAttributeByteBufferTestClass obj : objs) {
            BinaryAttributeByteBufferTestClass loaded = mapper.load(BinaryAttributeByteBufferTestClass.class, obj.getKey());
            assertEquals(obj, loaded);
        }

        // The whole batch is super large objects, none of them will be
        // processed
        largeObjs.clear();
        for (int i = 0; i < 5; i++) {
            BinaryAttributeByteBufferTestClass obj = getUniqueByteBufferObject(CONTENT_LENGTH * 30);
            largeObjs.add(obj);
        }
        if (DEBUG)
            System.err.println("failedBatches.size()=" + size);
        assertThat(failedBatches.size(), equalTo(1));
    }



    private NoSuchTableTestClass getuniqueBadObject() {
          NoSuchTableTestClass obj = new NoSuchTableTestClass();
          obj.setKey(String.valueOf(startKeyDebug++));
          return obj;
    }

    private NumberSetAttributeTestClass getUniqueNumericObject() {
        NumberSetAttributeTestClass obj = new NumberSetAttributeTestClass();
        obj.setKey(String.valueOf(startKeyDebug++));
        obj.setBigDecimalAttribute(toSet(new BigDecimal(startKey++), new BigDecimal(startKey++), new BigDecimal(startKey++)));
        obj.setBigIntegerAttribute(toSet(new BigInteger("" + startKey++), new BigInteger("" + startKey++), new BigInteger("" + startKey++)));
        obj.setByteObjectAttribute(toSet(new Byte(nextByte()), new Byte(nextByte()), new Byte(nextByte())));
        obj.setDoubleObjectAttribute(toSet(new Double("" + start++), new Double("" + start++), new Double("" + start++)));
        obj.setFloatObjectAttribute(toSet(new Float("" + start++), new Float("" + start++), new Float("" + start++)));
        obj.setIntegerAttribute(toSet(new Integer("" + start++), new Integer("" + start++), new Integer("" + start++)));
        obj.setLongObjectAttribute(toSet(new Long("" + start++), new Long("" + start++), new Long("" + start++)));
        obj.setBooleanAttribute(toSet(true, false));
        obj.setDateAttribute(toSet(new Date(startKey++), new Date(startKey++), new Date(startKey++)));
        Set<Calendar> cals = new HashSet<Calendar>();
        for ( Date d : obj.getDateAttribute() ) {
            Calendar cal = GregorianCalendar.getInstance();
            cal.setTime(d);
            cals.add(cal);
        }
        obj.setCalendarAttribute(toSet(cals));
        return obj;
    }

    private RangeKeyTestClass getUniqueRangeKeyObject() {
        RangeKeyTestClass obj = new RangeKeyTestClass();
        obj.setKey(startKey++);
        obj.setIntegerAttribute(toSet(start++, start++, start++));
        obj.setBigDecimalAttribute(new BigDecimal(startKey++));
        obj.setRangeKey(start++);
        obj.setStringAttribute("" + startKey++);
        obj.setStringSetAttribute(toSet("" + startKey++, "" + startKey++, "" + startKey++));
        return obj;
    }

    private String nextByte() {
        return "" + byteStart++ % Byte.MAX_VALUE;
    }
}
