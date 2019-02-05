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
import com.amazonaws.services.dynamodbv2.datamodeling.encryption.EncryptionFlags;
import com.amazonaws.services.dynamodbv2.mapper.encryption.StringSetAttributeTestClass;
import com.amazonaws.services.dynamodbv2.mapper.encryption.TestDynamoDBMapperFactory;
import com.amazonaws.services.dynamodbv2.mapper.encryption.TestEncryptionMaterialsProvider;
import com.amazonaws.services.dynamodbv2.model.AttributeValue;
import com.amazonaws.services.dynamodbv2.model.PutItemRequest;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.testng.Assert.assertEquals;



/**
 * Tests string set attributes
 */
public class StringSetAttributesITCase extends DynamoDBMapperCryptoIntegrationTestBase {

    private static final String ORIGINAL_NAME_ATTRIBUTE = "originalName";
    private static final String STRING_SET_ATTRIBUTE = "stringSetAttribute";
    private static final String EXTRA_ATTRIBUTE = "extra";
    private static final List<Map<String, AttributeValue>> attrs = new LinkedList<Map<String, AttributeValue>>();    

    // Test data
    static {
        for ( int i = 0; i < 5; i++ ) {
            Map<String, AttributeValue> attr = new HashMap<String, AttributeValue>();
            attr.put(KEY_NAME, new AttributeValue().withS("" + startKey++));
            attr.put(STRING_SET_ATTRIBUTE, new AttributeValue().withSS("" + ++startKey, "" + ++startKey, "" + ++startKey));
            attr.put(ORIGINAL_NAME_ATTRIBUTE, new AttributeValue().withSS("" + ++startKey, "" + ++startKey, "" + ++startKey));
            attr.put(EXTRA_ATTRIBUTE, new AttributeValue().withSS("" + ++startKey, "" + ++startKey, "" + ++startKey));
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
            Map<String, Set<EncryptionFlags>> flags = encryptor.allEncryptionFlagsExcept(attr, KEY_NAME);
            flags.remove(EXTRA_ATTRIBUTE); // exclude "extra" entirely since
                                           // it's not defined in the
                                           // StringSetAttributeTestClass pojo
            attr = encryptor.encryptRecord(attr, flags, context);
            dynamo.putItem(new PutItemRequest(TABLE_NAME, attr));
        }
    }
    
    @Test
    public void testLoad() throws Exception {
        DynamoDBMapper util = TestDynamoDBMapperFactory.createDynamoDBMapper(dynamo);
        
        for ( Map<String, AttributeValue> attr : attrs ) {
            StringSetAttributeTestClass x = util.load(StringSetAttributeTestClass.class, attr.get(KEY_NAME).getS());
            assertEquals(x.getKey(), attr.get(KEY_NAME).getS());
            assertSetsEqual(x.getStringSetAttribute(), toSet(attr.get(STRING_SET_ATTRIBUTE).getSS()));
            assertSetsEqual(x.getStringSetAttributeRenamed(), toSet(attr.get(ORIGINAL_NAME_ATTRIBUTE).getSS()));
        }        
    }

    /**
     * Tests saving only some attributes of an object.
     */
    @Test
    public void testIncompleteObject() {
        DynamoDBMapper util = TestDynamoDBMapperFactory.createDynamoDBMapper(dynamo);        

        StringSetAttributeTestClass obj = getUniqueObject();
        obj.setStringSetAttribute(null);
        util.save(obj);
        
        assertEquals(obj, util.load(StringSetAttributeTestClass.class, obj.getKey()));
        
        obj.setStringSetAttributeRenamed(null);
        util.save(obj);
        assertEquals(obj, util.load(StringSetAttributeTestClass.class, obj.getKey()));        
    }
    
    @Test
    public void testSave() throws Exception {
        List<StringSetAttributeTestClass> objs = new ArrayList<StringSetAttributeTestClass>();
        for ( int i = 0; i < 5; i++ ) {
            StringSetAttributeTestClass obj = getUniqueObject();
            objs.add(obj);
        }

        DynamoDBMapper util = TestDynamoDBMapperFactory.createDynamoDBMapper(dynamo);
        for (StringSetAttributeTestClass obj : objs) {
            util.save(obj);
        }

        for (StringSetAttributeTestClass obj : objs) {
            StringSetAttributeTestClass loaded = util.load(StringSetAttributeTestClass.class, obj.getKey());
            assertEquals(obj, loaded);
        }
    }
    
    @Test
    public void testUpdate() throws Exception {
        List<StringSetAttributeTestClass> objs = new ArrayList<StringSetAttributeTestClass>();
        for ( int i = 0; i < 5; i++ ) {
            StringSetAttributeTestClass obj = getUniqueObject();
            objs.add(obj);
        }

        DynamoDBMapper util = TestDynamoDBMapperFactory.createDynamoDBMapper(dynamo);
        for (StringSetAttributeTestClass obj : objs) {
            util.save(obj);
        }

        for ( StringSetAttributeTestClass obj : objs ) {
            StringSetAttributeTestClass replacement = getUniqueObject();
            replacement.setKey(obj.getKey());
            util.save(replacement);
            
            assertEquals(replacement, util.load(StringSetAttributeTestClass.class, obj.getKey()));
        }
    }

    private StringSetAttributeTestClass getUniqueObject() {
        StringSetAttributeTestClass obj = new StringSetAttributeTestClass();
        obj.setKey(String.valueOf(startKey++));
        obj.setStringSetAttribute(toSet(String.valueOf(startKey++), String.valueOf(startKey++), String.valueOf(startKey++)));
        obj.setStringSetAttributeRenamed(toSet(String.valueOf(startKey++), String.valueOf(startKey++), String.valueOf(startKey++)));
        return obj;
    }

}
