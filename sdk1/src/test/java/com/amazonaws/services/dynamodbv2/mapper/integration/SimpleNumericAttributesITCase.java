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
import com.amazonaws.services.dynamodbv2.datamodeling.encryption.DynamoDBEncryptor;
import com.amazonaws.services.dynamodbv2.datamodeling.encryption.EncryptionContext;
import com.amazonaws.services.dynamodbv2.mapper.encryption.NumberAttributeTestClass;
import com.amazonaws.services.dynamodbv2.mapper.encryption.TestDynamoDBMapperFactory;
import com.amazonaws.services.dynamodbv2.mapper.encryption.TestEncryptionMaterialsProvider;
import com.amazonaws.services.dynamodbv2.model.AttributeValue;
import com.amazonaws.services.dynamodbv2.model.GetItemRequest;
import com.amazonaws.services.dynamodbv2.model.GetItemResult;
import com.amazonaws.services.dynamodbv2.model.PutItemRequest;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertNull;


/**
 * Tests numeric attributes
 */
public class SimpleNumericAttributesITCase extends DynamoDBMapperCryptoIntegrationTestBase {

    private static final String INT_ATTRIBUTE = "intAttribute";
    private static final String INTEGER_ATTRIBUTE = "integerAttribute";
    private static final String FLOAT_ATTRIBUTE = "floatAttribute";
    private static final String FLOAT_OBJECT_ATTRIBUTE = "floatObjectAttribute";
    private static final String DOUBLE_ATTRIBUTE = "doubleAttribute";
    private static final String DOUBLE_OBJECT_ATTRIBUTE = "doubleObjectAttribute";
    private static final String BIG_INTEGER_ATTRIBUTE = "bigIntegerAttribute";
    private static final String BIG_DECIMAL_ATTRIBUTE = "bigDecimalAttribute";
    private static final String LONG_ATTRIBUTE = "longAttribute";
    private static final String LONG_OBJECT_ATTRIBUTE = "longObjectAttribute";
    private static final String BYTE_ATTRIBUTE = "byteAttribute";
    private static final String BYTE_OBJECT_ATTRIBUTE = "byteObjectAttribute";
    private static final String BOOLEAN_ATTRIBUTE = "booleanAttribute";
    private static final String BOOLEAN_OBJECT_ATTRIBUTE = "booleanObjectAttribute";
    private static final String SHORT_ATTRIBUTE = "shortAttribute";
    private static final String SHORT_OBJECT_ATTRIBUTE = "shortObjectAttribute";
    
    // We don't start with the current system millis like other tests because
    // it's out of the range of some data types
    private static int start = 1;
    private static int byteStart = -127;
    
    private static final List<Map<String, AttributeValue>> attrs = new LinkedList<Map<String, AttributeValue>>();

    // Test data
    static {
        for ( int i = 0; i < 5; i++ ) {
            Map<String, AttributeValue> attr = new HashMap<String, AttributeValue>();
            attr.put(KEY_NAME, new AttributeValue().withS("" + start++));
            attr.put(INT_ATTRIBUTE, new AttributeValue().withN("" + start++));
            attr.put(INTEGER_ATTRIBUTE, new AttributeValue().withN("" + start++));
            attr.put(FLOAT_ATTRIBUTE, new AttributeValue().withN("" + start++));
            attr.put(FLOAT_OBJECT_ATTRIBUTE, new AttributeValue().withN("" + start++));
            attr.put(DOUBLE_ATTRIBUTE, new AttributeValue().withN("" + start++));
            attr.put(DOUBLE_OBJECT_ATTRIBUTE, new AttributeValue().withN("" + start++));
            attr.put(BIG_INTEGER_ATTRIBUTE, new AttributeValue().withN("" + start++));
            attr.put(BIG_DECIMAL_ATTRIBUTE, new AttributeValue().withN("" + start++));
            attr.put(LONG_ATTRIBUTE, new AttributeValue().withN("" + start++));
            attr.put(LONG_OBJECT_ATTRIBUTE, new AttributeValue().withN("" + start++));
            attr.put(BYTE_ATTRIBUTE, new AttributeValue().withN("" + byteStart++));
            attr.put(BYTE_OBJECT_ATTRIBUTE, new AttributeValue().withN("" + byteStart++));
            attr.put(BOOLEAN_ATTRIBUTE, new AttributeValue().withN(start++ % 2 == 0 ? "1" : "0"));
            attr.put(BOOLEAN_OBJECT_ATTRIBUTE, new AttributeValue().withN(start++ % 2 == 0 ? "1" : "0"));
            attr.put(SHORT_ATTRIBUTE, new AttributeValue().withN("" + byteStart++));
            attr.put(SHORT_OBJECT_ATTRIBUTE, new AttributeValue().withN("" + byteStart++));
            attrs.add(attr);
        }
    };

    @BeforeClass
    public static void setUp() throws Exception {
        DynamoDBMapperCryptoIntegrationTestBase.setUp();
        DynamoDBEncryptor encryptor = DynamoDBEncryptor.getInstance(new TestEncryptionMaterialsProvider());
        EncryptionContext context = new EncryptionContext.Builder()
            .withHashKeyName(KEY_NAME)
            .withTableName(TABLE_NAME)
            .build();
        // Insert the data
        for ( Map<String, AttributeValue> attr : attrs ) {
            attr = encryptor.encryptAllFieldsExcept(attr, context, KEY_NAME);
            dynamo.putItem(new PutItemRequest(TABLE_NAME, attr));
        }
    }

    private NumberAttributeTestClass getKeyObject(String key) {
        NumberAttributeTestClass obj = new NumberAttributeTestClass();
        obj.setKey(key);
        return obj;
    }
    
    @Test
    public void testLoad() throws Exception {
        DynamoDBMapper util = TestDynamoDBMapperFactory.createDynamoDBMapper(dynamo);

        for ( Map<String, AttributeValue> attr : attrs ) {
            NumberAttributeTestClass x = util.load(getKeyObject(attr.get(KEY_NAME).getS()));
            assertEquals(x.getKey(), attr.get(KEY_NAME).getS());
            
            // Convert all numbers to the most inclusive type for easy comparison
            assertEquals(x.getBigDecimalAttribute(), new BigDecimal(attr.get(BIG_DECIMAL_ATTRIBUTE).getN()));
            assertEquals(new BigDecimal(x.getBigIntegerAttribute()), new BigDecimal(attr.get(BIG_INTEGER_ATTRIBUTE).getN()));
            assertEquals(new BigDecimal(x.getFloatAttribute()), new BigDecimal(attr.get(FLOAT_ATTRIBUTE).getN()));
            assertEquals(new BigDecimal(x.getFloatObjectAttribute()), new BigDecimal(attr.get(FLOAT_OBJECT_ATTRIBUTE).getN()));
            assertEquals(new BigDecimal(x.getDoubleAttribute()), new BigDecimal(attr.get(DOUBLE_ATTRIBUTE).getN()));
            assertEquals(new BigDecimal(x.getDoubleObjectAttribute()), new BigDecimal(attr.get(DOUBLE_OBJECT_ATTRIBUTE).getN()));
            assertEquals(new BigDecimal(x.getIntAttribute()), new BigDecimal(attr.get(INT_ATTRIBUTE).getN()));
            assertEquals(new BigDecimal(x.getIntegerAttribute()), new BigDecimal(attr.get(INTEGER_ATTRIBUTE).getN()));
            assertEquals(new BigDecimal(x.getLongAttribute()), new BigDecimal(attr.get(LONG_ATTRIBUTE).getN()));
            assertEquals(new BigDecimal(x.getLongObjectAttribute()), new BigDecimal(attr.get(LONG_OBJECT_ATTRIBUTE).getN()));
            assertEquals(new BigDecimal(x.getByteAttribute()), new BigDecimal(attr.get(BYTE_ATTRIBUTE).getN()));
            assertEquals(new BigDecimal(x.getByteObjectAttribute()), new BigDecimal(attr.get(BYTE_OBJECT_ATTRIBUTE).getN()));
            assertEquals(new BigDecimal(x.getShortAttribute()), new BigDecimal(attr.get(SHORT_ATTRIBUTE).getN()));
            assertEquals(new BigDecimal(x.getShortObjectAttribute()), new BigDecimal(attr.get(SHORT_OBJECT_ATTRIBUTE).getN()));
            assertEquals(x.isBooleanAttribute(), attr.get(BOOLEAN_ATTRIBUTE).getN().equals("1"));
            assertEquals((Object) x.getBooleanObjectAttribute(), (Object) attr.get(BOOLEAN_OBJECT_ATTRIBUTE).getN().equals("1"));
        }
        
        // Test loading an object that doesn't exist
        assertNull(util.load(getKeyObject("does not exist")));
    }
            
    @Test
    public void testSave() throws Exception {
        List<NumberAttributeTestClass> objs = new ArrayList<NumberAttributeTestClass>();
        for ( int i = 0; i < 5; i++ ) {
            NumberAttributeTestClass obj = getUniqueObject();            
            objs.add(obj);
        }

        DynamoDBMapper util = TestDynamoDBMapperFactory.createDynamoDBMapper(dynamo);
        for (NumberAttributeTestClass obj : objs) {
            util.save(obj);
        }

        for (NumberAttributeTestClass obj : objs) {
            NumberAttributeTestClass loaded = util.load(obj);
            loaded.setIgnored(obj.getIgnored());
            assertEquals(obj, loaded);
        }
    }   
    
    @Test
    public void testUpdate() throws Exception {
        List<NumberAttributeTestClass> objs = new ArrayList<NumberAttributeTestClass>();
        for ( int i = 0; i < 5; i++ ) {
            NumberAttributeTestClass obj = getUniqueObject();            
            objs.add(obj);
        }

        DynamoDBMapper util = TestDynamoDBMapperFactory.createDynamoDBMapper(dynamo);
        for (NumberAttributeTestClass obj : objs) {
            util.save(obj);
        }

        for ( NumberAttributeTestClass obj : objs ) {
            NumberAttributeTestClass replacement = getUniqueObject();
            replacement.setKey(obj.getKey());
            util.save(replacement);            
            
            NumberAttributeTestClass loadedObject = util.load(obj);
            
            assertFalse(replacement.getIgnored().equals(loadedObject.getIgnored()));
            loadedObject.setIgnored(replacement.getIgnored());
            assertEquals(replacement, loadedObject);
        }
    }
    
    /**
     * Tests automatically setting a hash key upon saving.
     */
    @Test
    public void testSetHashKey() throws Exception {
        List<NumberAttributeTestClass> objs = new ArrayList<NumberAttributeTestClass>();
        for ( int i = 0; i < 5; i++ ) {
            NumberAttributeTestClass obj = getUniqueObject();
            obj.setKey(null);
            objs.add(obj);            
        }

        DynamoDBMapper util = TestDynamoDBMapperFactory.createDynamoDBMapper(dynamo);
        for (NumberAttributeTestClass obj : objs) {
            assertNull(obj.getKey());
            util.save(obj);
            assertNotNull(obj.getKey());
            NumberAttributeTestClass loadedObject = util.load(obj);
            
            assertFalse(obj.getIgnored().equals(loadedObject.getIgnored()));
            loadedObject.setIgnored(obj.getIgnored());
            assertEquals(obj, loadedObject);
        }
    }

    @Test
    public void testDelete() throws Exception {
        NumberAttributeTestClass obj = getUniqueObject();
        DynamoDBMapper util = TestDynamoDBMapperFactory.createDynamoDBMapper(dynamo);
        util.save(obj);

        NumberAttributeTestClass loaded = util.load(NumberAttributeTestClass.class, obj.getKey());
        loaded.setIgnored(obj.getIgnored());
        assertEquals(obj, loaded);

        util.delete(obj);
        assertNull(util.load(NumberAttributeTestClass.class, obj.getKey()));
    }
    
    @Test
    public void performanceTest() throws Exception {
        NumberAttributeTestClass obj = getUniqueObject();
        DynamoDBMapper mapper = TestDynamoDBMapperFactory.createDynamoDBMapper(dynamo);
        mapper.save(obj);
        HashMap<String, AttributeValue> key = new HashMap<String, AttributeValue>();
        key.put(KEY_NAME, new AttributeValue().withS(obj.getKey()));
        GetItemResult item = dynamo.getItem(new GetItemRequest()
                .withTableName("aws-java-sdk-util-crypto").withKey(key));
        
        long start = System.currentTimeMillis();
        for (int i = 0; i < 10000; i++) {
            mapper.marshallIntoObject(NumberAttributeTestClass.class, item.getItem());
        }        
        
        long end = System.currentTimeMillis();
        
        System.err.println("time: " + (end - start));
    }
    
    private NumberAttributeTestClass getUniqueObject() {
        NumberAttributeTestClass obj = new NumberAttributeTestClass();
        obj.setKey(String.valueOf(startKey++));
        obj.setBigDecimalAttribute(new BigDecimal(startKey++));
        obj.setBigIntegerAttribute(new BigInteger("" + startKey++));
        obj.setByteAttribute((byte)byteStart++);
        obj.setByteObjectAttribute(new Byte("" + byteStart++));
        obj.setDoubleAttribute(new Double("" + start++));
        obj.setDoubleObjectAttribute(new Double("" + start++));
        obj.setFloatAttribute(new Float("" + start++));
        obj.setFloatObjectAttribute(new Float("" + start++));
        obj.setIntAttribute(new Integer("" + start++));
        obj.setIntegerAttribute(new Integer("" + start++));
        obj.setLongAttribute(new Long("" + start++));
        obj.setLongObjectAttribute(new Long("" + start++));
        obj.setShortAttribute(new Short("" + start++));
        obj.setShortObjectAttribute(new Short("" + start++));
        obj.setDateAttribute(new Date(startKey++));
        obj.setBooleanAttribute(start++ % 2 == 0);
        obj.setBooleanObjectAttribute(start++ % 2 == 0);
        obj.setIgnored("" + start++);
        Calendar cal = GregorianCalendar.getInstance();
        cal.setTime(new Date(startKey++));
        obj.setCalendarAttribute(cal);
        return obj;
    }


}
