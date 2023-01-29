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
package software.amazon.awssdk.enhanced.dynamodb.internal;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static software.amazon.awssdk.enhanced.dynamodb.internal.AttributeValueMarshaller.marshall;
import static software.amazon.awssdk.enhanced.dynamodb.internal.AttributeValueMarshaller.unmarshall;

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
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;

public class AttributeValueMarshallerTest {
    @Test
    public void testEmpty() {
        AttributeValue av = AttributeValue.builder().build();

        Exception exception = assertThrows(IllegalArgumentException.class, () ->
                        marshall(av));
    }

    @Test
    public void testNumber() {
        AttributeValue av = AttributeValue.builder().n("1337").build();
        assertEquals(av, unmarshall(marshall(av)));
    }

    @Test
    public void testString() {
        AttributeValue av = AttributeValue.builder().s("1337").build();
        assertEquals(av, unmarshall(marshall(av)));
    }

    @Test
    public void testByteBuffer() {
        AttributeValue av = AttributeValue.builder().b(SdkBytes.fromByteArray(new byte[]{0, 1, 2, 3, 4, 5})).build();
        assertEquals(av, unmarshall(marshall(av)));
    }

    // We can't use straight .equals for comparison because Attribute Values represents Sets
    // as Lists and so incorrectly does an ordered comparison

    @Test
    public void testNumberS() {
        AttributeValue av =
                AttributeValue.builder().ns(Collections.unmodifiableList(Arrays.asList("1337", "1", "5")))
                        .build();
        assertEquals(av, unmarshall(marshall(av)));
    }

    @Test
    public void testNumberSOrdering() {
        AttributeValue av1 =
                AttributeValue.builder().ns(Collections.unmodifiableList(Arrays.asList("1337", "1", "5")))
                        .build();
        AttributeValue av2 =
                AttributeValue.builder().ns(Collections.unmodifiableList(Arrays.asList("1", "5", "1337")))
                        .build();
        assertEquals(av1, av2);
        ByteBuffer buff1 = marshall(av1);
        ByteBuffer buff2 = marshall(av2);
        Assertions.assertEquals(buff1, buff2);
    }

    @Test
    public void testStringS() {
        AttributeValue av =
                AttributeValue.builder().ss(Collections.unmodifiableList(Arrays.asList("Bob", "Ann", "5"))).build();
        assertEquals(av, unmarshall(marshall(av)));
    }

    @Test
    public void testStringSOrdering() {
        AttributeValue av1 =
                AttributeValue.builder().ss(Collections.unmodifiableList(Arrays.asList("Bob", "Ann", "5"))).build();
        AttributeValue av2 =
                AttributeValue.builder().ss(Collections.unmodifiableList(Arrays.asList("Ann", "Bob", "5"))).build();
        assertEquals(av1, av2);
        ByteBuffer buff1 = marshall(av1);
        ByteBuffer buff2 = marshall(av2);
        Assertions.assertEquals(buff1, buff2);
    }

    @Test
    public void testByteBufferS() {
        AttributeValue av =
                AttributeValue.builder()
                        .bs(
                                Collections.unmodifiableList(
                                        Arrays.asList(
                                                SdkBytes.fromByteArray(new byte[]{0, 1, 2, 3, 4, 5}),
                                                SdkBytes.fromByteArray(new byte[]{5, 4, 3, 2, 1, 0, 0, 0, 5, 6, 7})))).build();
        assertEquals(av, unmarshall(marshall(av)));
    }

    @Test
    public void testByteBufferSOrdering() {
        AttributeValue av1 =
                AttributeValue.builder()
                        .bs(
                                Collections.unmodifiableList(
                                        Arrays.asList(
                                                SdkBytes.fromByteArray(new byte[]{0, 1, 2, 3, 4, 5}),
                                                SdkBytes.fromByteArray(new byte[]{5, 4, 3, 2, 1, 0, 0, 0, 5, 6, 7})))).build();
        AttributeValue av2 =
                AttributeValue.builder()
                        .bs(
                                Collections.unmodifiableList(
                                        Arrays.asList(
                                                SdkBytes.fromByteArray(new byte[]{5, 4, 3, 2, 1, 0, 0, 0, 5, 6, 7}),
                                                SdkBytes.fromByteArray(new byte[]{0, 1, 2, 3, 4, 5}))))
                        .build();

        assertEquals(av1, av2);
        ByteBuffer buff1 = marshall(av1);
        ByteBuffer buff2 = marshall(av2);
        Assertions.assertEquals(buff1, buff2);
    }

    @Test
    public void testBoolTrue() {
        AttributeValue av = AttributeValue.builder().bool(Boolean.TRUE).build();
        assertEquals(av, unmarshall(marshall(av)));
    }

    @Test
    public void testBoolFalse() {
        AttributeValue av = AttributeValue.builder().bool(Boolean.FALSE).build();
        assertEquals(av, unmarshall(marshall(av)));
    }

    @Test
    public void testNULL() {
        AttributeValue av = AttributeValue.builder().nul(Boolean.TRUE).build();
        assertEquals(av, unmarshall(marshall(av)));
    }

    @Test
    public void testActualNULL() {
        assertThrows(NullPointerException.class, () ->
            unmarshall(marshall(null)));
    }

    @Test
    public void testEmptyList() {
        AttributeValue av = AttributeValue.builder().l(Collections.emptyList()).build();
        assertEquals(av, unmarshall(marshall(av)));
    }

    @Test
    public void testListOfString() {
        AttributeValue av = AttributeValue.builder()
                .l(AttributeValue.builder()
                        .s("StringValue")
                        .build())
                .build();
        assertEquals(av, unmarshall(marshall(av)));
    }

    @Test
    public void testList() {
        AttributeValue av =
                AttributeValue.builder()
                        .l(
                                AttributeValue.builder().s("StringValue").build(),
                                AttributeValue.builder().n("1000").build(),
                                AttributeValue.builder().bool(Boolean.TRUE).build())
                        .build();
        assertEquals(av, unmarshall(marshall(av)));
    }

    @Test
    public void testListWithNull() {
        final AttributeValue av =
                AttributeValue.builder()
                        .l(
                                AttributeValue.builder().s("StringValue").build(),
                                AttributeValue.builder().n("1000").build(),
                                AttributeValue.builder().bool(Boolean.TRUE).build(),
                                null)
                        .build();

        try {
            ByteBuffer result = marshall(av);
            Assertions.fail("Unexpected success");
        } catch (final NullPointerException npe) {
            Assertions.assertEquals(
                    "Encountered null list entry value while marshalling attribute value AttributeValue(L=[AttributeValue(S=StringValue), AttributeValue(N=1000), AttributeValue(BOOL=true), null])",
                    npe.getMessage());
        }
    }

    @Test
    public void testListDuplicates() {
        AttributeValue av =
                AttributeValue.builder()
                        .l(
                                AttributeValue.builder().n("1000").build(),
                                AttributeValue.builder().n("1000").build(),
                                AttributeValue.builder().n("1000").build(),
                                AttributeValue.builder().n("1000").build())
                        .build();
        AttributeValue result = unmarshall(marshall(av));
        assertEquals(av, result);
        Assertions.assertEquals(4, result.l().size());
    }

    @Test
    public void testComplexList() {
        final List<AttributeValue> list1 =
                Arrays.asList(
                        AttributeValue.builder().s("StringValue").build(),
                        AttributeValue.builder().n("1000").build(),
                        AttributeValue.builder().bool(Boolean.TRUE).build());
        final List<AttributeValue> list22 =
                Arrays.asList(
                        AttributeValue.builder().s("AWS").build(),
                        AttributeValue.builder().n("-3700").build(),
                        AttributeValue.builder().bool(Boolean.FALSE).build());
        final List<AttributeValue> list2 =
                Arrays.asList(
                        AttributeValue.builder().l(list22).build(),
                        AttributeValue.builder().nul(Boolean.TRUE).build());
        AttributeValue av =
                AttributeValue.builder()
                        .l(
                                AttributeValue.builder().s("StringValue1").build(),
                                AttributeValue.builder().l(list1).build(),
                                AttributeValue.builder().n("50").build(),
                                AttributeValue.builder().l(list2).build())
                        .build();
        assertEquals(av, unmarshall(marshall(av)));
    }

    @Test
    public void testEmptyMap() {
        Map<String, AttributeValue> map = new HashMap<String, AttributeValue>();
        AttributeValue av = AttributeValue.builder().m(map).build();
        assertEquals(av, unmarshall(marshall(av)));
    }

    @Test
    public void testSimpleMap() {
        Map<String, AttributeValue> map = new HashMap<String, AttributeValue>();
        map.put("KeyValue", AttributeValue.builder().s("ValueValue").build());
        AttributeValue av = AttributeValue.builder().m(map).build();
        assertEquals(av, unmarshall(marshall(av)));
    }

    @Test
    public void testSimpleMapWithNull() {
        final Map<String, AttributeValue> map = new HashMap<String, AttributeValue>();
        map.put("KeyValue", AttributeValue.builder().s("ValueValue").build());
        map.put("NullKeyValue", null);

        final AttributeValue av = AttributeValue.builder().m(map).build();

        try {
            marshall(av);
            Assertions.fail("Unexpected success: " + av);
        } catch (final NullPointerException npe) {
            // Map entries may permute under nondeterministic Java API
            String npeMessage = npe.getMessage();

            Assertions.assertEquals(npeMessage,
                    "Encountered null map value for key NullKeyValue while marshalling attribute value " +
                            "AttributeValue(M={KeyValue=AttributeValue(S=ValueValue), NullKeyValue=null})");
        }
    }

    @Test
    public void testMapOrdering() {
        LinkedHashMap<String, AttributeValue> m1 = new LinkedHashMap<String, AttributeValue>();
        LinkedHashMap<String, AttributeValue> m2 = new LinkedHashMap<String, AttributeValue>();

        m1.put("Value1", AttributeValue.builder().n("1").build());
        m1.put("Value2", AttributeValue.builder().bool(Boolean.TRUE).build());

        m2.put("Value2", AttributeValue.builder().bool(Boolean.TRUE).build());
        m2.put("Value1", AttributeValue.builder().n("1").build());

        AttributeValue av1 = AttributeValue.builder().m(m1).build();
        AttributeValue av2 = AttributeValue.builder().m(m2).build();

        ByteBuffer buff1 = marshall(av1);
        ByteBuffer buff2 = marshall(av2);
        Assertions.assertEquals(buff1, buff2);
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
        Assertions.assertArrayEquals(oldBytes, newBytes);

        AttributeValue oldObject = unmarshall(ByteBuffer.wrap(oldBytes));
        assertEquals(oldObject, newObject);
    }

    private static final String COMPLEX_ATTRIBUTE_MARSHALLED =
            "AE0AAAADAHM"
                    + "AAAAJSW5uZXJMaXN0AEwAAAAGAHMAAAALQ29tcGxleExpc3QAbgAAAAE1AGIAA"
                    + "AAGAAECAwQFAEwAAAAFAD8BAAAAAABMAAAAAQA/AABNAAAAAwBzAAAABFBpbms"
                    + "AcwAAAAVGbG95ZABzAAAABFRlc3QAPwEAcwAAAAdWZXJzaW9uAG4AAAABMQAAA"
                    + "E0AAAADAHMAAAAETGlzdABMAAAABQBuAAAAATUAbgAAAAE0AG4AAAABMwBuAAA"
                    + "AATIAbgAAAAExAHMAAAADTWFwAE0AAAABAHMAAAAGTmVzdGVkAD8BAHMAAAAEV"
                    + "HJ1ZQA/AQBzAAAACVNpbmdsZU1hcABNAAAAAQBzAAAAA0ZPTwBzAAAAA0JBUgB"
                    + "zAAAACVN0cmluZ1NldABTAAAAAwAAAANiYXIAAAADYmF6AAAAA2Zvbw==";

    private static AttributeValue buildComplexAttributeValue() {
        Map<String, AttributeValue> floydMap = new HashMap<>();
        floydMap.put("Pink", AttributeValue.builder().s("Floyd").build());
        floydMap.put("Version", AttributeValue.builder().n("1").build());
        floydMap.put("Test", AttributeValue.builder().bool(Boolean.TRUE).build());
        List<AttributeValue> floydList =
                Arrays.asList(
                        AttributeValue.builder().bool(Boolean.TRUE).build(),
                        AttributeValue.builder().nul(Boolean.TRUE).build(),
                        AttributeValue.builder().nul(Boolean.TRUE).build(),
                        AttributeValue.builder().l(AttributeValue.builder().bool(Boolean.FALSE).build()).build(),
                        AttributeValue.builder().m(floydMap).build());

        List<AttributeValue> nestedList =
                Arrays.asList(
                        AttributeValue.builder().n("5").build(),
                        AttributeValue.builder().n("4").build(),
                        AttributeValue.builder().n("3").build(),
                        AttributeValue.builder().n("2").build(),
                        AttributeValue.builder().n("1").build());
        Map<String, AttributeValue> nestedMap = new HashMap<String, AttributeValue>();
        nestedMap.put("True", AttributeValue.builder().bool(Boolean.TRUE).build());
        nestedMap.put("List", AttributeValue.builder().l(nestedList).build());
        nestedMap.put(
                "Map",
                AttributeValue.builder()
                        .m(
                                Collections.singletonMap("Nested", AttributeValue.builder().bool(Boolean.TRUE).build()))
                        .build());

        List<AttributeValue> innerList =
                Arrays.asList(
                        AttributeValue.builder().s("ComplexList").build(),
                        AttributeValue.builder().n("5").build(),
                        AttributeValue.builder().b(SdkBytes.fromByteArray(new byte[]{0, 1, 2, 3, 4, 5})).build(),
                        AttributeValue.builder().l(floydList).build(),
                        AttributeValue.builder().nul(Boolean.TRUE).build(),
                        AttributeValue.builder().m(nestedMap).build());

        Map<String, AttributeValue> map = new HashMap<>();
        map.put(
                "SingleMap",
                AttributeValue.builder()
                        .m(Collections.singletonMap("FOO", AttributeValue.builder().s("BAR").build()))
                        .build());
        map.put("InnerList", AttributeValue.builder().l(innerList).build());
        map.put("StringSet", AttributeValue.builder().ss("foo", "bar", "baz").build());

        return AttributeValue.builder().m(map).build();
    }

    private void assertEquals(AttributeValue o1, AttributeValue o2) {
        Assertions.assertEquals(o1.b(), o2.b());
        assertSetsEqual(o1.bs(), o2.bs());
        Assertions.assertEquals(o1.n(), o2.n());
        assertSetsEqual(o1.ns(), o2.ns());
        Assertions.assertEquals(o1.s(), o2.s());
        assertSetsEqual(o1.ss(), o2.ss());
        Assertions.assertEquals(o1.bool(), o2.bool());
        Assertions.assertEquals(o1.nul(), o2.nul());

        if (o1.l() != null) {
            Assertions.assertNotNull(o2.l());
            final List<AttributeValue> l1 = o1.l();
            final List<AttributeValue> l2 = o2.l();
            Assertions.assertEquals(l1.size(), l2.size());
            for (int x = 0; x < l1.size(); ++x) {
                assertEquals(l1.get(x), l2.get(x));
            }
        }

        if (o1.hasM()) {
            Assertions.assertTrue(o2.hasM());
            final Map<String, AttributeValue> m1 = o1.m();
            final Map<String, AttributeValue> m2 = o2.m();
            Assertions.assertEquals(m1.size(), m2.size());
            for (Map.Entry<String, AttributeValue> entry : m1.entrySet()) {
                assertEquals(entry.getValue(), m2.get(entry.getKey()));
            }
        }
    }

    private <T> void assertSetsEqual(Collection<T> c1, Collection<T> c2) {
        Assertions.assertFalse(c1 == null ^ c2 == null);
        if (c1 != null) {
            Set<T> s1 = new HashSet<T>(c1);
            Set<T> s2 = new HashSet<T>(c2);
            Assertions.assertEquals(s1, s2);
        }
    }
}
