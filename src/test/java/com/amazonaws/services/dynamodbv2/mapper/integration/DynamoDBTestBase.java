/*
 * Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

import com.amazonaws.services.dynamodbv2.AmazonDynamoDB;
import com.amazonaws.services.dynamodbv2.local.embedded.DynamoDBEmbedded;

import java.math.BigDecimal;
import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

import static org.testng.Assert.fail;
import static org.testng.AssertJUnit.assertTrue;

public class DynamoDBTestBase {
    protected static AmazonDynamoDB dynamo;

    public static void setUpTestBase() {
        dynamo = DynamoDBEmbedded.create();
    }

    public static AmazonDynamoDB getClient() {
        if (dynamo == null) {
            setUpTestBase();
        }
        return dynamo;
    }

    protected static <T extends Object> Set<T> toSet(T... array) {
        Set<T> set = new HashSet<T>();
        for (T t : array) {
            set.add(t);
        }
        return set;
    }

    protected static <T extends Object> void assertSetsEqual(Collection<T> expected, Collection<T> given) {
        Set<T> givenCopy = new HashSet<T>();
        givenCopy.addAll(given);
        for (T e : expected) {
            if (!givenCopy.remove(e)) {
                fail("Expected element not found: " + e);
            }
        }

        assertTrue("Unexpected elements found: " + givenCopy, givenCopy.isEmpty());
    }

    protected static void assertNumericSetsEquals(Set<? extends Number> expected, Collection<String> given) {
        Set<BigDecimal> givenCopy = new HashSet<BigDecimal>();
        for (String s : given) {
            BigDecimal bd = new BigDecimal(s);
            givenCopy.add(bd.setScale(0));
        }

        Set<BigDecimal> expectedCopy = new HashSet<BigDecimal>();
        for (Number n : expected) {
            BigDecimal bd = new BigDecimal(n.toString());
            expectedCopy.add(bd.setScale(0));
        }

        assertSetsEqual(expectedCopy, givenCopy);
    }
    protected static <T extends Object> Set<T> toSet(Collection<T> collection) {
        Set<T> set = new HashSet<T>();
        for (T t : collection) {
            set.add(t);
        }
        return set;
    }

    protected static byte[] generateByteArray(int length) {
        byte[] bytes = new byte[length];
        for (int i = 0; i < length; i++) {
            bytes[i] = (byte) (i % Byte.MAX_VALUE);
        }
        return bytes;
    }

}
