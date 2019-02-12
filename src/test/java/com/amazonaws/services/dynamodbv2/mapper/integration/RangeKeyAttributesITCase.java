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
import com.amazonaws.services.dynamodbv2.mapper.encryption.RangeKeyTestClass;
import com.amazonaws.services.dynamodbv2.mapper.encryption.TestDynamoDBMapperFactory;
import com.amazonaws.services.dynamodbv2.mapper.encryption.TestEncryptionMaterialsProvider;
import com.amazonaws.services.dynamodbv2.model.AttributeValue;
import com.amazonaws.services.dynamodbv2.model.PutItemRequest;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.fail;


/**
 * Tests range and hash key combination
 */
public class RangeKeyAttributesITCase extends DynamoDBMapperCryptoIntegrationTestBase {

    private static final String RANGE_KEY = "rangeKey";
    private static final String INTEGER_ATTRIBUTE = "integerSetAttribute";
    private static final String BIG_DECIMAL_ATTRIBUTE = "bigDecimalAttribute";
    private static final String STRING_SET_ATTRIBUTE = "stringSetAttribute";
    private static final String STRING_ATTRIBUTE = "stringAttribute";
    private static final String VERSION_ATTRIBUTE = "version";


    // We don't start with the current system millis like other tests because
    // it's out of the range of some data types
    private static int start = 1;

    private static final List<Map<String, AttributeValue>> attrs = new LinkedList<Map<String, AttributeValue>>();

    // Test data
    static {
        for ( int i = 0; i < 5; i++ ) {
            Map<String, AttributeValue> attr = new HashMap<String, AttributeValue>();
            attr.put(KEY_NAME, new AttributeValue().withN("" + startKey++));
            attr.put(RANGE_KEY, new AttributeValue().withN("" + start++));
            attr.put(INTEGER_ATTRIBUTE, new AttributeValue().withNS("" + start++, "" + start++, "" + start++));
            attr.put(BIG_DECIMAL_ATTRIBUTE, new AttributeValue().withN("" + start++));
            attr.put(STRING_ATTRIBUTE, new AttributeValue().withS("" + start++));
            attr.put(STRING_SET_ATTRIBUTE, new AttributeValue().withSS("" + start++, "" + start++, "" + start++));
            attr.put(VERSION_ATTRIBUTE, new AttributeValue().withN("1"));

            attrs.add(attr);
        }
    };

    @BeforeClass
    public static void setUp() throws Exception {
        setUpTableWithRangeAttribute();
        DynamoDBEncryptor encryptor = DynamoDBEncryptor.getInstance(new TestEncryptionMaterialsProvider());
        EncryptionContext context = new EncryptionContext.Builder()
            .withHashKeyName(KEY_NAME)
            .withRangeKeyName(RANGE_KEY)
            .withTableName(TABLE_WITH_RANGE_ATTRIBUTE)
            .build();
        // Insert the data
        for ( Map<String, AttributeValue> attr : attrs ) {
            attr = encryptor.encryptAllFieldsExcept(attr, context, KEY_NAME,
                    RANGE_KEY, VERSION_ATTRIBUTE, BIG_DECIMAL_ATTRIBUTE);
            dynamo.putItem(new PutItemRequest(TABLE_WITH_RANGE_ATTRIBUTE, attr));
        }
    }

    @Test
    public void testLoad() throws Exception {
        DynamoDBMapper util = TestDynamoDBMapperFactory.createDynamoDBMapper(dynamo);

        for ( Map<String, AttributeValue> attr : attrs ) {
            RangeKeyTestClass x = util.load(newRangeKey(Long.parseLong(attr.get(KEY_NAME).getN()),
                    Double.parseDouble(attr.get(RANGE_KEY).getN())));

            // Convert all numbers to the most inclusive type for easy
            // comparison
            assertEquals(new BigDecimal(x.getKey()), new BigDecimal(attr.get(KEY_NAME).getN()));
            assertEquals(new BigDecimal(x.getRangeKey()), new BigDecimal(attr.get(RANGE_KEY).getN()));
            assertEquals(new BigDecimal(x.getVersion()), new BigDecimal(attr.get(VERSION_ATTRIBUTE).getN()));
            assertEquals(x.getBigDecimalAttribute(), new BigDecimal(attr.get(BIG_DECIMAL_ATTRIBUTE).getN()));
            assertNumericSetsEquals(x.getIntegerAttribute(), attr.get(INTEGER_ATTRIBUTE).getNS());
            assertEquals(x.getStringAttribute(), attr.get(STRING_ATTRIBUTE).getS());
            assertSetsEqual(x.getStringSetAttribute(), toSet(attr.get(STRING_SET_ATTRIBUTE).getSS()));
        }
    }
    
    private RangeKeyTestClass newRangeKey(long hashKey, double rangeKey) {
        RangeKeyTestClass obj = new RangeKeyTestClass();
        obj.setKey(hashKey);
        obj.setRangeKey(rangeKey);
        return obj;
    }

    @Test
    public void testSave() throws Exception {
        List<RangeKeyTestClass> objs = new ArrayList<RangeKeyTestClass>();
        for ( int i = 0; i < 5; i++ ) {
            RangeKeyTestClass obj = getUniqueObject();
            objs.add(obj);
        }

        DynamoDBMapper util = TestDynamoDBMapperFactory.createDynamoDBMapper(dynamo);
        for (RangeKeyTestClass obj : objs) {
            util.save(obj);
        }

        for (RangeKeyTestClass obj : objs) {
            RangeKeyTestClass loaded = util.load(RangeKeyTestClass.class, obj.getKey(), obj.getRangeKey());
            assertEquals(obj, loaded);
        }
    }

    @Test
    public void testUpdate() throws Exception {
        List<RangeKeyTestClass> objs = new ArrayList<RangeKeyTestClass>();
        for ( int i = 0; i < 5; i++ ) {
            RangeKeyTestClass obj = getUniqueObject();
            objs.add(obj);
        }

        DynamoDBMapper util = TestDynamoDBMapperFactory.createDynamoDBMapper(dynamo);
        for (RangeKeyTestClass obj : objs) {
            util.save(obj);
        }

        for ( RangeKeyTestClass obj : objs ) {
            RangeKeyTestClass replacement = getUniqueObject();
            replacement.setKey(obj.getKey());
            replacement.setRangeKey(obj.getRangeKey());
            replacement.setVersion(obj.getVersion());
            util.save(replacement);

            RangeKeyTestClass loadedObject = util.load(RangeKeyTestClass.class, obj.getKey(), obj.getRangeKey());
            assertEquals(replacement, loadedObject);

            // If we try to update the old version, we should get an error
            replacement.setVersion(replacement.getVersion() - 1);
            try {
                util.save(replacement);
                fail("Should have thrown an exception");
            } catch ( Exception expected ) {
            }
        }
    }

    private RangeKeyTestClass getUniqueObject() {
        RangeKeyTestClass obj = new RangeKeyTestClass();
        obj.setKey(startKey++);
        obj.setIntegerAttribute(toSet(start++, start++, start++));
        obj.setBigDecimalAttribute(new BigDecimal(startKey++));
        obj.setRangeKey(start++);
        obj.setStringAttribute("" + startKey++);
        obj.setStringSetAttribute(toSet("" + startKey++, "" + startKey++, "" + startKey++));
        return obj;
    }
}
