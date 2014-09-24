/*
 * Copyright 2014 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 *  http://aws.amazon.com/apache2.0
 *
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */
package com.amazonaws.services.dynamodbv2.datamodeling.internal;

import static com.amazonaws.services.dynamodbv2.datamodeling.internal.AttributeValueMarshaller.marshall;
import static com.amazonaws.services.dynamodbv2.datamodeling.internal.AttributeValueMarshaller.unmarshall;

import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import org.junit.Assert;
import org.junit.Test;

import com.amazonaws.services.dynamodbv2.model.AttributeValue;

public class AttributeValueMarshallerTest {
    @Test
    public void testEmpty() {
        AttributeValue av = new AttributeValue();
        assertEquals(av, unmarshall(marshall(av)));
    }
    
    @Test
    public void testNumber() {
        AttributeValue av = new AttributeValue().withN("1337");
        assertEquals(av, unmarshall(marshall(av)));
    }
    
    @Test
    public void testString() {
        AttributeValue av = new AttributeValue().withS("1337");
        assertEquals(av, unmarshall(marshall(av)));
    }
    
    @Test
    public void testByteBuffer() {
        AttributeValue av = new AttributeValue().withB(ByteBuffer.wrap(new byte[] {0, 1, 2, 3, 4, 5}));
        assertEquals(av, unmarshall(marshall(av)));
    }

    // We can't use straight .equals for comparison because Attribute Values represents Sets
    // as Lists and so incorrectly does an ordered comparison
    
    @Test
    public void testNumberS() {
        AttributeValue av = new AttributeValue().withNS(Collections.unmodifiableList(Arrays.asList("1337", "1", "5")));
        assertEquals(av, unmarshall(marshall(av)));
    }
    
    @Test
    public void testStringS() {
        AttributeValue av = new AttributeValue().withSS(Collections.unmodifiableList(Arrays.asList("Bob", "Ann", "5")));
        assertEquals(av, unmarshall(marshall(av)));
    }
    
    @Test
    public void testByteBufferS() {
        AttributeValue av = new AttributeValue().withBS(Collections.unmodifiableList(
                Arrays.asList(ByteBuffer.wrap(new byte[] {0, 1, 2, 3, 4, 5}),
                ByteBuffer.wrap(new byte[] {5, 4, 3, 2, 1, 0, 0, 0, 5, 6, 7}))));
        assertEquals(av, unmarshall(marshall(av)));
    }
    
    private void assertEquals(AttributeValue o1, AttributeValue o2) {
        Assert.assertEquals(o1.getB(), o2.getB());
        assertSetsEqual(o1.getBS(), o2.getBS());
        Assert.assertEquals(o1.getN(), o2.getN());
        assertSetsEqual(o1.getNS(), o2.getNS());
        Assert.assertEquals(o1.getS(), o2.getS());
        assertSetsEqual(o1.getSS(), o2.getSS());
    }
    
    private <T> void assertSetsEqual(Collection<T> c1, Collection<T> c2) {
        Assert.assertFalse(c1 == null ^ c2 == null);
        if (c1 != null) {
            Set<T> s1 = new HashSet<T>(c1);
            Set<T> s2 = new HashSet<T>(c2);
            Assert.assertEquals(s1, s2);
        }
    }
}
