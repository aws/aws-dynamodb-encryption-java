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
import com.amazonaws.services.dynamodbv2.mapper.encryption.BinaryAttributeByteArrayTestClass;
import com.amazonaws.services.dynamodbv2.mapper.encryption.BinaryAttributeByteBufferTestClass;
import com.amazonaws.services.dynamodbv2.mapper.encryption.TestDynamoDBMapperFactory;
import com.amazonaws.services.dynamodbv2.mapper.encryption.TestEncryptionMaterialsProvider;
import com.amazonaws.services.dynamodbv2.model.AttributeValue;
import com.amazonaws.services.dynamodbv2.model.PutItemRequest;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertTrue;


/**
 * Tests simple string attributes
 */
public class BinaryAttributesITCase extends DynamoDBMapperCryptoIntegrationTestBase {

    private static final String BINARY_ATTRIBUTE = "binaryAttribute";
    private static final String BINARY_SET_ATTRIBUTE = "binarySetAttribute";
    private static final List<Map<String, AttributeValue>> attrs = new LinkedList<Map<String, AttributeValue>>();
    private static final int contentLength = 512;
    // Test data
    static {
            Map<String, AttributeValue> attr = new HashMap<String, AttributeValue>();
            attr.put(KEY_NAME, new AttributeValue().withS("" + startKey++));
            attr.put(BINARY_ATTRIBUTE, new AttributeValue().withB(ByteBuffer.wrap(generateByteArray(contentLength))));
            attr.put(BINARY_SET_ATTRIBUTE, new AttributeValue().
            		withBS(ByteBuffer.wrap(generateByteArray(contentLength)),
            				ByteBuffer.wrap(generateByteArray(contentLength + 1))));
            attrs.add(attr);

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

    @Test
    public void testLoad() throws Exception {
        DynamoDBMapper util = TestDynamoDBMapperFactory.createDynamoDBMapper(dynamo);

        for ( Map<String, AttributeValue> attr : attrs ) {
        	// test BinaryAttributeClass
            BinaryAttributeByteBufferTestClass x = util.load(BinaryAttributeByteBufferTestClass.class, attr.get(KEY_NAME).getS());
            assertEquals(x.getKey(), attr.get(KEY_NAME).getS());
            assertEquals(x.getBinaryAttribute(), ByteBuffer.wrap(generateByteArray(contentLength)));
            assertTrue(x.getBinarySetAttribute().contains(ByteBuffer.wrap(generateByteArray(contentLength))));
            assertTrue(x.getBinarySetAttribute().contains(ByteBuffer.wrap(generateByteArray(contentLength + 1))));

            // test BinaryAttributeByteArrayTestClass
            BinaryAttributeByteArrayTestClass y = util.load(BinaryAttributeByteArrayTestClass.class, attr.get(KEY_NAME).getS());
            assertEquals(y.getKey(), attr.get(KEY_NAME).getS());
            assertTrue(Arrays.equals(y.getBinaryAttribute(), (generateByteArray(contentLength))));
            assertTrue(2 == y.getBinarySetAttribute().size());
            assertTrue(setContainsBytes(y.getBinarySetAttribute(), generateByteArray(contentLength)));
            assertTrue(setContainsBytes(y.getBinarySetAttribute(), generateByteArray(contentLength+1)));
        }

    }

    @Test
    public void testSave() {
    	// test BinaryAttributeClass
        List<BinaryAttributeByteBufferTestClass> byteBufferObjs = new ArrayList<BinaryAttributeByteBufferTestClass>();
        for ( int i = 0; i < 5; i++ ) {
        	BinaryAttributeByteBufferTestClass obj = getUniqueByteBufferObject(contentLength);
            byteBufferObjs.add(obj);
        }

        DynamoDBMapper util = TestDynamoDBMapperFactory.createDynamoDBMapper(dynamo);
        for (BinaryAttributeByteBufferTestClass obj : byteBufferObjs) {
            util.save(obj);
        }

        for (BinaryAttributeByteBufferTestClass obj : byteBufferObjs) {
        	BinaryAttributeByteBufferTestClass loaded = util.load(BinaryAttributeByteBufferTestClass.class, obj.getKey());
        	assertEquals(loaded.getKey(), obj.getKey());
        	assertEquals(loaded.getBinaryAttribute(), ByteBuffer.wrap(generateByteArray(contentLength)));
            assertTrue(loaded.getBinarySetAttribute().contains(ByteBuffer.wrap(generateByteArray(contentLength))));
        }

        // test BinaryAttributeByteArrayTestClass
        List<BinaryAttributeByteArrayTestClass> bytesObjs = new ArrayList<BinaryAttributeByteArrayTestClass>();
        for ( int i = 0; i < 5; i++ ) {
        	BinaryAttributeByteArrayTestClass obj = getUniqueBytesObject(contentLength);
            bytesObjs.add(obj);
        }

        for (BinaryAttributeByteArrayTestClass obj : bytesObjs) {
            util.save(obj);
        }

        for (BinaryAttributeByteArrayTestClass obj : bytesObjs) {
        	BinaryAttributeByteArrayTestClass loaded = util.load(BinaryAttributeByteArrayTestClass.class, obj.getKey());
        	 assertEquals(loaded.getKey(), obj.getKey());
             assertTrue(Arrays.equals(loaded.getBinaryAttribute(), (generateByteArray(contentLength))));
             assertTrue(1 == loaded.getBinarySetAttribute().size());
             assertTrue(setContainsBytes(loaded.getBinarySetAttribute(), generateByteArray(contentLength)));
        }
    }

    /**
     * Tests saving an incomplete object into DynamoDB
     */
    @Test
    public void testIncompleteObject() {
    	// test BinaryAttributeClass
    	BinaryAttributeByteBufferTestClass byteBufferObj = getUniqueByteBufferObject(contentLength);
        byteBufferObj.setBinarySetAttribute(null);
        DynamoDBMapper util = TestDynamoDBMapperFactory.createDynamoDBMapper(dynamo);
        util.save(byteBufferObj);

        BinaryAttributeByteBufferTestClass loadedX = util.load(BinaryAttributeByteBufferTestClass.class, byteBufferObj.getKey());
        assertEquals(loadedX.getKey(), byteBufferObj.getKey());
    	assertEquals(loadedX.getBinaryAttribute(), ByteBuffer.wrap(generateByteArray(contentLength)));
    	assertEquals(loadedX.getBinarySetAttribute(), null);


        // test removing an attribute
        assertNotNull(byteBufferObj.getBinaryAttribute());
        byteBufferObj.setBinaryAttribute(null);
        util.save(byteBufferObj);

        loadedX = util.load(BinaryAttributeByteBufferTestClass.class, byteBufferObj.getKey());
        assertEquals(loadedX.getKey(), byteBufferObj.getKey());
    	assertEquals(loadedX.getBinaryAttribute(), null);
    	assertEquals(loadedX.getBinarySetAttribute(), null);

    	// test BinaryAttributeByteArrayTestClass
    	BinaryAttributeByteArrayTestClass bytesObj = getUniqueBytesObject(contentLength);
        bytesObj.setBinarySetAttribute(null);
        util.save(bytesObj);

        BinaryAttributeByteArrayTestClass loadedY = util.load(BinaryAttributeByteArrayTestClass.class, bytesObj.getKey());
        assertEquals(loadedY.getKey(), bytesObj.getKey());
    	assertTrue(Arrays.equals(loadedY.getBinaryAttribute(), generateByteArray(contentLength)));
    	assertEquals(loadedY.getBinarySetAttribute(), null);


        // test removing an attribute
        assertNotNull(bytesObj.getBinaryAttribute());
        bytesObj.setBinaryAttribute(null);
        util.save(bytesObj);

        loadedY = util.load(BinaryAttributeByteArrayTestClass.class, bytesObj.getKey());
        assertEquals(loadedY.getKey(), bytesObj.getKey());
    	assertEquals(loadedY.getBinaryAttribute(), null);
    	assertEquals(loadedY.getBinarySetAttribute(), null);
    }

    @Test
    public void testUpdate() {
    	// test BinaryAttributeClass
        List<BinaryAttributeByteBufferTestClass> byteBufferObjs = new ArrayList<BinaryAttributeByteBufferTestClass>();
        for ( int i = 0; i < 5; i++ ) {
        	BinaryAttributeByteBufferTestClass obj = getUniqueByteBufferObject(contentLength);
            byteBufferObjs.add(obj);
        }

        DynamoDBMapper util = TestDynamoDBMapperFactory.createDynamoDBMapper(dynamo);
        for (BinaryAttributeByteBufferTestClass obj : byteBufferObjs) {
            util.save(obj);
        }

        for ( BinaryAttributeByteBufferTestClass obj : byteBufferObjs ) {
        	BinaryAttributeByteBufferTestClass replacement = getUniqueByteBufferObject(contentLength - 1);
            replacement.setKey(obj.getKey());
            util.save(replacement);

            BinaryAttributeByteBufferTestClass loaded = util.load(BinaryAttributeByteBufferTestClass.class, obj.getKey());
            assertEquals(loaded.getKey(), obj.getKey());
        	assertEquals(loaded.getBinaryAttribute(), ByteBuffer.wrap(generateByteArray(contentLength - 1)));
            assertTrue(loaded.getBinarySetAttribute().contains(ByteBuffer.wrap(generateByteArray(contentLength - 1))));

        }

        // test BinaryAttributeByteArrayTestClass
        List<BinaryAttributeByteArrayTestClass> bytesObj = new ArrayList<BinaryAttributeByteArrayTestClass>();
        for ( int i = 0; i < 5; i++ ) {
        	BinaryAttributeByteArrayTestClass obj = getUniqueBytesObject(contentLength);
            bytesObj.add(obj);
        }

        for (BinaryAttributeByteArrayTestClass obj : bytesObj) {
            util.save(obj);
        }

        for ( BinaryAttributeByteArrayTestClass obj : bytesObj ) {
        	BinaryAttributeByteArrayTestClass replacement = getUniqueBytesObject(contentLength - 1);
            replacement.setKey(obj.getKey());
            util.save(replacement);

             BinaryAttributeByteArrayTestClass loaded = util.load(BinaryAttributeByteArrayTestClass.class, obj.getKey());
        	 assertEquals(loaded.getKey(), obj.getKey());
             assertTrue(Arrays.equals(loaded.getBinaryAttribute(), (generateByteArray(contentLength - 1))));
             assertTrue(1 == loaded.getBinarySetAttribute().size());
             assertTrue(setContainsBytes(loaded.getBinarySetAttribute(), generateByteArray(contentLength - 1)));

        }
    }

    @Test
    public void testDelete() throws Exception {
    	// test BinaryAttributeClass
    	BinaryAttributeByteBufferTestClass byteBufferObj = getUniqueByteBufferObject(contentLength);
        DynamoDBMapper util = TestDynamoDBMapperFactory.createDynamoDBMapper(dynamo);
        util.save(byteBufferObj);

        util.delete(byteBufferObj);
        assertNull(util.load(BinaryAttributeByteBufferTestClass.class, byteBufferObj.getKey()));

        // test BinaryAttributeByteArrayTestClass
        BinaryAttributeByteArrayTestClass bytesObj = getUniqueBytesObject(contentLength);
        util.save(bytesObj);

        util.delete(bytesObj);
        assertNull(util.load(BinaryAttributeByteArrayTestClass.class, bytesObj.getKey()));

    }

    private BinaryAttributeByteArrayTestClass getUniqueBytesObject(int contentLength) {
    	BinaryAttributeByteArrayTestClass obj = new BinaryAttributeByteArrayTestClass();
        obj.setKey(String.valueOf(startKey++));
        obj.setBinaryAttribute(generateByteArray(contentLength));
        Set<byte[]> byteArray = new HashSet<byte[]>();
        byteArray.add(generateByteArray(contentLength));
        obj.setBinarySetAttribute(byteArray);
        return obj;
    }

    private boolean setContainsBytes(Set<byte[]> set, byte[] bytes) {
    	     Iterator<byte[]> iter = set.iterator();
    	     while (iter.hasNext()) {
    	    	 if (Arrays.equals(iter.next(), bytes))
    	    		 return true;
    	     }
    	return false;
    }

}
