/*
 * Copyright 2014-2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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
package software.amazon.cryptools.dynamodbencryptionclientsdk2.internal;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.startsWith;
import static org.testng.AssertJUnit.assertEquals;
import static org.testng.AssertJUnit.assertFalse;
import static org.testng.AssertJUnit.assertNotNull;
import static org.testng.AssertJUnit.fail;
import static software.amazon.cryptools.dynamodbencryptionclientsdk2.internal.AttributeValueMarshaller.marshall;
import static software.amazon.cryptools.dynamodbencryptionclientsdk2.internal.AttributeValueMarshaller.unmarshall;
import static java.util.Collections.emptyList;
import static java.util.Collections.singletonList;
import static java.util.Collections.unmodifiableList;

import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.testng.annotations.Test;

import software.amazon.cryptools.dynamodbencryptionclientsdk2.testing.AttributeValueBuilder;

import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;

public class AttributeValueMarshallerTest {
    @Test(expectedExceptions = IllegalArgumentException.class)
    public void testEmpty() {
        AttributeValue av = AttributeValue.builder().build();
        marshall(av);
    }
    
    @Test
    public void testNumber() {
        AttributeValue av = AttributeValue.builder().n("1337").build();
        assertAttributesAreEqual(av, unmarshall(marshall(av)));
    }
    
    @Test
    public void testString() {
        AttributeValue av = AttributeValue.builder().s("1337").build();
        assertAttributesAreEqual(av, unmarshall(marshall(av)));
    }
    
    @Test
    public void testByteBuffer() {
        AttributeValue av = AttributeValue.builder().b(SdkBytes.fromByteArray(new byte[] {0, 1, 2, 3, 4, 5})).build();
        assertAttributesAreEqual(av, unmarshall(marshall(av)));
    }

    // We can't use straight .equals for comparison because Attribute Values represents Sets
    // as Lists and so incorrectly does an ordered comparison
    
    @Test
    public void testNumberS() {
        AttributeValue av = AttributeValue.builder().ns(unmodifiableList(Arrays.asList("1337", "1", "5"))).build();
        assertAttributesAreEqual(av, unmarshall(marshall(av)));
    }

    @Test
    public void testNumberSOrdering() {
        AttributeValue av1 = AttributeValue.builder().ns(unmodifiableList(Arrays.asList("1337", "1", "5"))).build();
        AttributeValue av2 = AttributeValue.builder().ns(unmodifiableList(Arrays.asList("1", "5", "1337"))).build();
        assertAttributesAreEqual(av1, av2);
        ByteBuffer buff1 = marshall(av1);
        ByteBuffer buff2 = marshall(av2);
        assertEquals(buff1, buff2);
    }

    @Test
    public void testStringS() {
        AttributeValue av = AttributeValue.builder().ss(unmodifiableList(Arrays.asList("Bob", "Ann", "5"))).build();
        assertAttributesAreEqual(av, unmarshall(marshall(av)));
    }
    
    @Test
    public void testStringSOrdering() {
        AttributeValue av1 = AttributeValue.builder().ss(unmodifiableList(Arrays.asList("Bob", "Ann", "5"))).build();
        AttributeValue av2 = AttributeValue.builder().ss(unmodifiableList(Arrays.asList("Ann", "Bob", "5"))).build();
        assertAttributesAreEqual(av1, av2);
        ByteBuffer buff1 = marshall(av1);
        ByteBuffer buff2 = marshall(av2);
        assertEquals(buff1, buff2);
    }

    @Test
    public void testByteBufferS() {
        AttributeValue av = AttributeValue.builder().bs(unmodifiableList(
                Arrays.asList(SdkBytes.fromByteArray(new byte[] {0, 1, 2, 3, 4, 5}),
                SdkBytes.fromByteArray(new byte[] {5, 4, 3, 2, 1, 0, 0, 0, 5, 6, 7})))).build();
        assertAttributesAreEqual(av, unmarshall(marshall(av)));
    }

    @Test
    public void testByteBufferSOrdering() {
        AttributeValue av1 = AttributeValue.builder().bs(unmodifiableList(
                Arrays.asList(SdkBytes.fromByteArray(new byte[] {0, 1, 2, 3, 4, 5}),
                SdkBytes.fromByteArray(new byte[] {5, 4, 3, 2, 1, 0, 0, 0, 5, 6, 7})))).build();
        AttributeValue av2 = AttributeValue.builder().bs(unmodifiableList(
                Arrays.asList(SdkBytes.fromByteArray(new byte[] {5, 4, 3, 2, 1, 0, 0, 0, 5, 6, 7}),
                              SdkBytes.fromByteArray(new byte[]{0, 1, 2, 3, 4, 5})))).build();

        assertAttributesAreEqual(av1, av2);
        ByteBuffer buff1 = marshall(av1);
        ByteBuffer buff2 = marshall(av2);
        assertEquals(buff1, buff2);
    }

    @Test
    public void testBoolTrue() {
        AttributeValue av = AttributeValue.builder().bool(Boolean.TRUE).build();
        assertAttributesAreEqual(av, unmarshall(marshall(av)));
    }

    @Test
    public void testBoolFalse() {
        AttributeValue av = AttributeValue.builder().bool(Boolean.FALSE).build();
        assertAttributesAreEqual(av, unmarshall(marshall(av)));
    }

    @Test
    public void testNULL() {
        AttributeValue av = AttributeValue.builder().nul(Boolean.TRUE).build();
        assertAttributesAreEqual(av, unmarshall(marshall(av)));
    }

    @Test(expectedExceptions = NullPointerException.class)
    public void testActualNULL() {
        unmarshall(marshall(null));
    }

    @Test
    public void testEmptyList() {
        AttributeValue av = AttributeValue.builder().l(emptyList()).build();
        assertAttributesAreEqual(av, unmarshall(marshall(av)));
    }

    @Test
    public void testListOfString() {
        AttributeValue av =
            AttributeValue.builder().l(singletonList(AttributeValue.builder().s("StringValue").build())).build();
        assertAttributesAreEqual(av, unmarshall(marshall(av)));
    }

    @Test
    public void testList() {
        AttributeValue av = AttributeValueBuilder.ofL(
            AttributeValueBuilder.ofS("StringValue"),
            AttributeValueBuilder.ofN("1000"),
            AttributeValueBuilder.ofBool(Boolean.TRUE));
        assertAttributesAreEqual(av, unmarshall(marshall(av)));
    }

    @Test
    public void testListWithNull() {
        final AttributeValue av = AttributeValueBuilder.ofL(
                AttributeValueBuilder.ofS("StringValue"),
                AttributeValueBuilder.ofN("1000"),
                AttributeValueBuilder.ofBool(Boolean.TRUE),
                null);

        try {
            marshall(av);
        } catch (NullPointerException e) {
            assertThat(e.getMessage(),
                       startsWith("Encountered null list entry value while marshalling attribute value"));
        }
    }

    @Test
    public void testListDuplicates() {
        AttributeValue av = AttributeValueBuilder.ofL(
                AttributeValueBuilder.ofN("1000"),
                AttributeValueBuilder.ofN("1000"),
                AttributeValueBuilder.ofN("1000"),
                AttributeValueBuilder.ofN("1000"));
        AttributeValue result = unmarshall(marshall(av));
        assertAttributesAreEqual(av, result);
        assertEquals(4, result.l().size());
    }

    @Test
    public void testComplexList() {
        final List<AttributeValue> list1 = Arrays.asList(
                AttributeValueBuilder.ofS("StringValue"),
                AttributeValueBuilder.ofN("1000"),
                AttributeValueBuilder.ofBool(Boolean.TRUE));
        final List<AttributeValue> list22 = Arrays.asList(
                AttributeValueBuilder.ofS("AWS"),
                AttributeValueBuilder.ofN("-3700"),
                AttributeValueBuilder.ofBool(Boolean.FALSE));
        final List<AttributeValue> list2 = Arrays.asList(
                AttributeValueBuilder.ofL(list22),
                AttributeValueBuilder.ofNull());
        AttributeValue av = AttributeValueBuilder.ofL(
                AttributeValueBuilder.ofS("StringValue1"),
                AttributeValueBuilder.ofL(list1),
                AttributeValueBuilder.ofN("50"),
                AttributeValueBuilder.ofL(list2));
        assertAttributesAreEqual(av, unmarshall(marshall(av)));
    }

    @Test
    public void testEmptyMap() {
        Map<String,AttributeValue> map = new HashMap<>();
        AttributeValue av = AttributeValueBuilder.ofM(map);
        assertAttributesAreEqual(av, unmarshall(marshall(av)));
    }

    @Test
    public void testSimpleMap() {
        Map<String, AttributeValue> map = new HashMap<>();
        map.put("KeyValue", AttributeValueBuilder.ofS("ValueValue"));
        AttributeValue av = AttributeValueBuilder.ofM(map);
        assertAttributesAreEqual(av, unmarshall(marshall(av)));
    }

    @Test
    public void testSimpleMapWithNull() {
        final Map<String, AttributeValue> map = new HashMap<>();
        map.put("KeyValue", AttributeValueBuilder.ofS("ValueValue"));
        map.put("NullKeyValue", null);

        final AttributeValue av = AttributeValueBuilder.ofM(map);

        try {
            marshall(av);
            fail("NullPointerException should have been thrown");
        } catch (NullPointerException e) {
            assertThat(e.getMessage(), startsWith("Encountered null map value for key NullKeyValue while marshalling "
                                          + "attribute value"));
        }
    }

    @Test
    public void testMapOrdering() {
        LinkedHashMap<String, AttributeValue> m1 = new LinkedHashMap<>();
        LinkedHashMap<String, AttributeValue> m2 = new LinkedHashMap<>();

        m1.put("Value1", AttributeValueBuilder.ofN("1"));
        m1.put("Value2", AttributeValueBuilder.ofBool(Boolean.TRUE));

        m2.put("Value2", AttributeValueBuilder.ofBool(Boolean.TRUE));
        m2.put("Value1", AttributeValueBuilder.ofN("1"));

        AttributeValue av1 = AttributeValueBuilder.ofM(m1);
        AttributeValue av2 = AttributeValueBuilder.ofM(m2);

        ByteBuffer buff1 = marshall(av1);
        ByteBuffer buff2 = marshall(av2);
        assertEquals(buff1, buff2);
        assertAttributesAreEqual(av1, unmarshall(buff1));
        assertAttributesAreEqual(av1, unmarshall(buff2));
        assertAttributesAreEqual(av2, unmarshall(buff1));
        assertAttributesAreEqual(av2, unmarshall(buff2));
    }

    @Test
    public void testComplexMap() {
        AttributeValue av = buildComplexAttributeValue();
        assertAttributesAreEqual(av, unmarshall(marshall(av)));
    }

    // This test ensures that an AttributeValue marshalled by an older
    // version of this library still unmarshalls correctly. It also
    // ensures that old and new marshalling is identical.
    @Test
    public void testVersioningCompatibility() {
        AttributeValue newObject = buildComplexAttributeValue();
        byte[] oldBytes = Base64.getDecoder().decode(COMPLEX_ATTRIBUTE_MARSHALLED);
        byte[] newBytes = marshall(newObject).array();
        assertThat(oldBytes, is(newBytes));

        AttributeValue oldObject = unmarshall(ByteBuffer.wrap(oldBytes));
        assertAttributesAreEqual(oldObject, newObject);
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
        Map<String, AttributeValue> floydMap = new HashMap<>();
        floydMap.put("Pink", AttributeValueBuilder.ofS("Floyd"));
        floydMap.put("Version", AttributeValueBuilder.ofN("1"));
        floydMap.put("Test", AttributeValueBuilder.ofBool(Boolean.TRUE));
        List<AttributeValue> floydList = Arrays.asList(
                AttributeValueBuilder.ofBool(Boolean.TRUE),
                AttributeValueBuilder.ofNull(),
                AttributeValueBuilder.ofNull(),
                AttributeValueBuilder.ofL(AttributeValueBuilder.ofBool(Boolean.FALSE)),
                AttributeValueBuilder.ofM(floydMap)
                );

        List<AttributeValue> nestedList = Arrays.asList(
                AttributeValueBuilder.ofN("5"),
                AttributeValueBuilder.ofN("4"),
                AttributeValueBuilder.ofN("3"),
                AttributeValueBuilder.ofN("2"),
                AttributeValueBuilder.ofN("1")
                );
        Map<String, AttributeValue> nestedMap = new HashMap<>();
        nestedMap.put("True", AttributeValueBuilder.ofBool(Boolean.TRUE));
        nestedMap.put("List", AttributeValueBuilder.ofL(nestedList));
        nestedMap.put("Map", AttributeValueBuilder.ofM(
                Collections.singletonMap("Nested",
                        AttributeValueBuilder.ofBool(Boolean.TRUE))));

        List<AttributeValue> innerList = Arrays.asList(
                AttributeValueBuilder.ofS("ComplexList"),
                AttributeValueBuilder.ofN("5"),
                AttributeValueBuilder.ofB(new byte[] {0, 1, 2, 3, 4, 5}),
                AttributeValueBuilder.ofL(floydList),
                AttributeValueBuilder.ofNull(),
                AttributeValueBuilder.ofM(nestedMap)
                );

        Map<String, AttributeValue> result = new HashMap<>();
        result.put("SingleMap", AttributeValueBuilder.ofM(
                Collections.singletonMap("FOO", AttributeValueBuilder.ofS("BAR"))));
        result.put("InnerList", AttributeValueBuilder.ofL(innerList));
        result.put("StringSet", AttributeValueBuilder.ofSS("foo", "bar", "baz"));
        return AttributeValue.builder().m(Collections.unmodifiableMap(result)).build();
    }

    private void assertAttributesAreEqual(AttributeValue o1, AttributeValue o2) {
        assertEquals(o1.b(), o2.b());
        assertSetsEqual(o1.bs(), o2.bs());
        assertEquals(o1.n(), o2.n());
        assertSetsEqual(o1.ns(), o2.ns());
        assertEquals(o1.s(), o2.s());
        assertSetsEqual(o1.ss(), o2.ss());
        assertEquals(o1.bool(), o2.bool());
        assertEquals(o1.nul(), o2.nul());

        if (o1.l() != null) {
            assertNotNull(o2.l());
            final List<AttributeValue> l1 = o1.l();
            final List<AttributeValue> l2 = o2.l();
            assertEquals(l1.size(), l2.size());
            for (int x = 0; x < l1.size(); ++x) {
                assertAttributesAreEqual(l1.get(x), l2.get(x));
            }
        }

        if (o1.m() != null) {
            assertNotNull(o2.m());
            final Map<String, AttributeValue> m1 = o1.m();
            final Map<String, AttributeValue> m2 = o2.m();
            assertEquals(m1.size(), m2.size());
            for (Map.Entry<String, AttributeValue> entry : m1.entrySet()) {
                assertAttributesAreEqual(entry.getValue(), m2.get(entry.getKey()));
            }
        }
    }

    private <T> void assertSetsEqual(Collection<T> c1, Collection<T> c2) {
        assertFalse(c1 == null ^ c2 == null);
        if (c1 != null) {
            Set<T> s1 = new HashSet<>(c1);
            Set<T> s2 = new HashSet<>(c2);
            assertEquals(s1, s2);
        }
    }
}
