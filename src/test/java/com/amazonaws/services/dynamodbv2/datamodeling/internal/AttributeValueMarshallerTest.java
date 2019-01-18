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

import com.amazonaws.services.dynamodbv2.model.AttributeValue;
import com.amazonaws.util.Base64;
import org.testng.Assert;
import org.testng.AssertJUnit;
import org.testng.annotations.Test;

import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static com.amazonaws.services.dynamodbv2.datamodeling.internal.AttributeValueMarshaller.marshall;
import static com.amazonaws.services.dynamodbv2.datamodeling.internal.AttributeValueMarshaller.unmarshall;

public class AttributeValueMarshallerTest {
    @Test(expectedExceptions = IllegalArgumentException.class)
    public void testEmpty() {
        AttributeValue av = new AttributeValue();
        marshall(av);
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
        AttributeValue av = new AttributeValue().withB(ByteBuffer.wrap(new byte[]{0, 1, 2, 3, 4, 5}));
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
    public void testNumberSOrdering() {
        AttributeValue av1 = new AttributeValue().withNS(Collections.unmodifiableList(Arrays.asList("1337", "1", "5")));
        AttributeValue av2 = new AttributeValue().withNS(Collections.unmodifiableList(Arrays.asList("1", "5", "1337")));
        assertEquals(av1, av2);
        ByteBuffer buff1 = marshall(av1);
        ByteBuffer buff2 = marshall(av2);
        Assert.assertEquals(buff1, buff2);
    }

    @Test
    public void testStringS() {
        AttributeValue av = new AttributeValue().withSS(Collections.unmodifiableList(Arrays.asList("Bob", "Ann", "5")));
        assertEquals(av, unmarshall(marshall(av)));
    }

    @Test
    public void testStringSOrdering() {
        AttributeValue av1 = new AttributeValue().withSS(Collections.unmodifiableList(Arrays.asList("Bob", "Ann", "5")));
        AttributeValue av2 = new AttributeValue().withSS(Collections.unmodifiableList(Arrays.asList("Ann", "Bob", "5")));
        assertEquals(av1, av2);
        ByteBuffer buff1 = marshall(av1);
        ByteBuffer buff2 = marshall(av2);
        Assert.assertEquals(buff1, buff2);
    }

    @Test
    public void testByteBufferS() {
        AttributeValue av = new AttributeValue().withBS(Collections.unmodifiableList(
                Arrays.asList(ByteBuffer.wrap(new byte[]{0, 1, 2, 3, 4, 5}),
                        ByteBuffer.wrap(new byte[]{5, 4, 3, 2, 1, 0, 0, 0, 5, 6, 7}))));
        assertEquals(av, unmarshall(marshall(av)));
    }

    @Test
    public void testByteBufferSOrdering() {
        AttributeValue av1 = new AttributeValue().withBS(Collections.unmodifiableList(
                Arrays.asList(ByteBuffer.wrap(new byte[]{0, 1, 2, 3, 4, 5}),
                        ByteBuffer.wrap(new byte[]{5, 4, 3, 2, 1, 0, 0, 0, 5, 6, 7}))));
        AttributeValue av2 = new AttributeValue().withBS(Collections.unmodifiableList(
                Arrays.asList(ByteBuffer.wrap(new byte[]{5, 4, 3, 2, 1, 0, 0, 0, 5, 6, 7}),
                        ByteBuffer.wrap(new byte[]{0, 1, 2, 3, 4, 5})
                )));

        assertEquals(av1, av2);
        ByteBuffer buff1 = marshall(av1);
        ByteBuffer buff2 = marshall(av2);
        Assert.assertEquals(buff1, buff2);
    }

    @Test
    public void testBoolTrue() {
        AttributeValue av = new AttributeValue().withBOOL(Boolean.TRUE);
        assertEquals(av, unmarshall(marshall(av)));
    }

    @Test
    public void testBoolFalse() {
        AttributeValue av = new AttributeValue().withBOOL(Boolean.FALSE);
        assertEquals(av, unmarshall(marshall(av)));
    }

    @Test
    public void testNULL() {
        AttributeValue av = new AttributeValue().withNULL(Boolean.TRUE);
        assertEquals(av, unmarshall(marshall(av)));
    }

    @Test(expectedExceptions = NullPointerException.class)
    public void testActualNULL() {
        unmarshall(marshall(null));
    }

    @Test
    public void testEmptyList() {
        AttributeValue av = new AttributeValue().withL();
        assertEquals(av, unmarshall(marshall(av)));
    }

    @Test
    public void testListOfString() {
        AttributeValue av = new AttributeValue().withL(new AttributeValue().withS("StringValue"));
        assertEquals(av, unmarshall(marshall(av)));
    }

    @Test
    public void testList() {
        AttributeValue av = new AttributeValue().withL(
                new AttributeValue().withS("StringValue"),
                new AttributeValue().withN("1000"),
                new AttributeValue().withBOOL(Boolean.TRUE));
        assertEquals(av, unmarshall(marshall(av)));
    }

    @Test
    public void testListWithNull() {
        final AttributeValue av = new AttributeValue().withL(
                new AttributeValue().withS("StringValue"),
                new AttributeValue().withN("1000"),
                new AttributeValue().withBOOL(Boolean.TRUE),
                null);

        try {
            marshall(av);
            Assert.fail("Unexpected success");
        } catch (final NullPointerException npe) {
            Assert.assertEquals("Encountered null list entry value while marshalling attribute value {L: [{S: StringValue,}, {N: 1000,}, {BOOL: true}, null],}",
                    npe.getMessage());
        }
    }

    @Test
    public void testListDuplicates() {
        AttributeValue av = new AttributeValue().withL(
                new AttributeValue().withN("1000"),
                new AttributeValue().withN("1000"),
                new AttributeValue().withN("1000"),
                new AttributeValue().withN("1000"));
        AttributeValue result = unmarshall(marshall(av));
        assertEquals(av, result);
        Assert.assertEquals(4, result.getL().size());
    }

    @Test
    public void testComplexList() {
        final List<AttributeValue> list1 = Arrays.asList(
                new AttributeValue().withS("StringValue"),
                new AttributeValue().withN("1000"),
                new AttributeValue().withBOOL(Boolean.TRUE));
        final List<AttributeValue> list22 = Arrays.asList(
                new AttributeValue().withS("AWS"),
                new AttributeValue().withN("-3700"),
                new AttributeValue().withBOOL(Boolean.FALSE));
        final List<AttributeValue> list2 = Arrays.asList(
                new AttributeValue().withL(list22),
                new AttributeValue().withNULL(Boolean.TRUE));
        AttributeValue av = new AttributeValue().withL(
                new AttributeValue().withS("StringValue1"),
                new AttributeValue().withL(list1),
                new AttributeValue().withN("50"),
                new AttributeValue().withL(list2));
        assertEquals(av, unmarshall(marshall(av)));
    }

    @Test
    public void testEmptyMap() {
        Map<String, AttributeValue> map = new HashMap<String, AttributeValue>();
        AttributeValue av = new AttributeValue().withM(map);
        assertEquals(av, unmarshall(marshall(av)));
    }

    @Test
    public void testSimpleMap() {
        Map<String, AttributeValue> map = new HashMap<String, AttributeValue>();
        map.put("KeyValue", new AttributeValue().withS("ValueValue"));
        AttributeValue av = new AttributeValue().withM(map);
        assertEquals(av, unmarshall(marshall(av)));
    }

    @Test
    public void testSimpleMapWithNull() {
        final Map<String, AttributeValue> map = new HashMap<String, AttributeValue>();
        map.put("KeyValue", new AttributeValue().withS("ValueValue"));
        map.put("NullKeyValue", null);

        final AttributeValue av = new AttributeValue().withM(map);

        try {
            marshall(av);
            Assert.fail("Unexpected success");
        } catch (final NullPointerException npe) {
            Assert.assertEquals("Encountered null map value for key NullKeyValue while marshalling attribute value {M: {KeyValue={S: ValueValue,}, NullKeyValue=null},}",
                    npe.getMessage());
        }
    }

    @Test
    public void testMapOrdering() {
        LinkedHashMap<String, AttributeValue> m1 = new LinkedHashMap<String, AttributeValue>();
        LinkedHashMap<String, AttributeValue> m2 = new LinkedHashMap<String, AttributeValue>();

        m1.put("Value1", new AttributeValue().withN("1"));
        m1.put("Value2", new AttributeValue().withBOOL(Boolean.TRUE));

        m2.put("Value2", new AttributeValue().withBOOL(Boolean.TRUE));
        m2.put("Value1", new AttributeValue().withN("1"));

        AttributeValue av1 = new AttributeValue().withM(m1);
        AttributeValue av2 = new AttributeValue().withM(m2);

        ByteBuffer buff1 = marshall(av1);
        ByteBuffer buff2 = marshall(av2);
        Assert.assertEquals(buff1, buff2);
        assertEquals(av1, unmarshall(buff1));
        assertEquals(av1, unmarshall(buff2));
        assertEquals(av2, unmarshall(buff1));
        assertEquals(av2, unmarshall(buff2));
    }

    @Test
    public void testComplexMap() {
        AttributeValue av = buildComplexAttributeValue();
        assertEquals(av, unmarshall(marshall(av)));
    }

    // This test ensures that an AttributeValue marshalled by an older
    // version of this library still unmarshalls correctly. It also
    // ensures that old and new marshalling is identical.
    @Test
    public void testVersioningCompatibility() {
        AttributeValue newObject = buildComplexAttributeValue();
        byte[] oldBytes = Base64.decode(COMPLEX_ATTRIBUTE_MARSHALLED);
        byte[] newBytes = marshall(newObject).array();
        AssertJUnit.assertArrayEquals(oldBytes, newBytes);

        AttributeValue oldObject = unmarshall(ByteBuffer.wrap(oldBytes));
        assertEquals(oldObject, newObject);
    }

    private static final String COMPLEX_ATTRIBUTE_MARSHALLED = "AE0AAAADAHM" +
            "AAAAJSW5uZXJMaXN0AEwAAAAGAHMAAAALQ29tcGxleExpc3QAbgAAAAE1AGIAA" +
            "AAGAAECAwQFAEwAAAAFAD8BAAAAAABMAAAAAQA/AABNAAAAAwBzAAAABFBpbms" +
            "AcwAAAAVGbG95ZABzAAAABFRlc3QAPwEAcwAAAAdWZXJzaW9uAG4AAAABMQAAA" +
            "E0AAAADAHMAAAAETGlzdABMAAAABQBuAAAAATUAbgAAAAE0AG4AAAABMwBuAAA" +
            "AATIAbgAAAAExAHMAAAADTWFwAE0AAAABAHMAAAAGTmVzdGVkAD8BAHMAAAAEV" +
            "HJ1ZQA/AQBzAAAACVNpbmdsZU1hcABNAAAAAQBzAAAAA0ZPTwBzAAAAA0JBUgB" +
            "zAAAACVN0cmluZ1NldABTAAAAAwAAAANiYXIAAAADYmF6AAAAA2Zvbw==";

    private static AttributeValue buildComplexAttributeValue() {
        Map<String, AttributeValue> floydMap = new HashMap<String, AttributeValue>();
        floydMap.put("Pink", new AttributeValue().withS("Floyd"));
        floydMap.put("Version", new AttributeValue().withN("1"));
        floydMap.put("Test", new AttributeValue().withBOOL(Boolean.TRUE));
        List<AttributeValue> floydList = Arrays.asList(
                new AttributeValue().withBOOL(Boolean.TRUE),
                new AttributeValue().withNULL(Boolean.TRUE),
                new AttributeValue().withNULL(Boolean.TRUE),
                new AttributeValue().withL(new AttributeValue().withBOOL(Boolean.FALSE)),
                new AttributeValue().withM(floydMap)
        );

        List<AttributeValue> nestedList = Arrays.asList(
                new AttributeValue().withN("5"),
                new AttributeValue().withN("4"),
                new AttributeValue().withN("3"),
                new AttributeValue().withN("2"),
                new AttributeValue().withN("1")
        );
        Map<String, AttributeValue> nestedMap = new HashMap<String, AttributeValue>();
        nestedMap.put("True", new AttributeValue().withBOOL(Boolean.TRUE));
        nestedMap.put("List", new AttributeValue().withL(nestedList));
        nestedMap.put("Map", new AttributeValue().withM(
                Collections.singletonMap("Nested",
                        new AttributeValue().withBOOL(Boolean.TRUE))));

        List<AttributeValue> innerList = Arrays.asList(
                new AttributeValue().withS("ComplexList"),
                new AttributeValue().withN("5"),
                new AttributeValue().withB(ByteBuffer.wrap(new byte[]{0, 1, 2, 3, 4, 5})),
                new AttributeValue().withL(floydList),
                new AttributeValue().withNULL(Boolean.TRUE),
                new AttributeValue().withM(nestedMap)
        );

        AttributeValue av = new AttributeValue();
        av.addMEntry("SingleMap", new AttributeValue().withM(
                Collections.singletonMap("FOO", new AttributeValue().withS("BAR"))));
        av.addMEntry("InnerList", new AttributeValue().withL(innerList));
        av.addMEntry("StringSet", new AttributeValue().withSS("foo", "bar", "baz"));
        return av;
    }

    private void assertEquals(AttributeValue o1, AttributeValue o2) {
        Assert.assertEquals(o1.getB(), o2.getB());
        assertSetsEqual(o1.getBS(), o2.getBS());
        Assert.assertEquals(o1.getN(), o2.getN());
        assertSetsEqual(o1.getNS(), o2.getNS());
        Assert.assertEquals(o1.getS(), o2.getS());
        assertSetsEqual(o1.getSS(), o2.getSS());
        Assert.assertEquals(o1.getBOOL(), o2.getBOOL());
        Assert.assertEquals(o1.getNULL(), o2.getNULL());

        if (o1.getL() != null) {
            Assert.assertNotNull(o2.getL());
            final List<AttributeValue> l1 = o1.getL();
            final List<AttributeValue> l2 = o2.getL();
            Assert.assertEquals(l1.size(), l2.size());
            for (int x = 0; x < l1.size(); ++x) {
                assertEquals(l1.get(x), l2.get(x));
            }
        }

        if (o1.getM() != null) {
            Assert.assertNotNull(o2.getM());
            final Map<String, AttributeValue> m1 = o1.getM();
            final Map<String, AttributeValue> m2 = o2.getM();
            Assert.assertEquals(m1.size(), m2.size());
            for (Map.Entry<String, AttributeValue> entry : m1.entrySet()) {
                assertEquals(entry.getValue(), m2.get(entry.getKey()));
            }
        }
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
