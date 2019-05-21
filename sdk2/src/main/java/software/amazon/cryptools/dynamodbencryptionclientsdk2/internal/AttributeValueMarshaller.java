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

import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.math.BigDecimal;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import software.amazon.awssdk.core.BytesWrapper;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.core.util.DefaultSdkAutoConstructList;
import software.amazon.awssdk.core.util.DefaultSdkAutoConstructMap;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;


/**
 * @author Greg Rubin 
 */
public class AttributeValueMarshaller {
    private static final Charset UTF8 = Charset.forName("UTF-8");
    private static final int TRUE_FLAG = 1;
    private static final int FALSE_FLAG = 0;

    private AttributeValueMarshaller() {
        // Prevent instantiation
    }

    /**
     * Marshalls the data using a TLV (Tag-Length-Value) encoding. The tag may be 'b', 'n', 's',
     * '?', '\0' to represent a ByteBuffer, Number, String, Boolean, or Null respectively. The tag
     * may also be capitalized (for 'b', 'n', and 's',) to represent an array of that type. If an
     * array is stored, then a four-byte big-endian integer is written representing the number of
     * array elements. If a ByteBuffer is stored, the length of the buffer is stored as a four-byte
     * big-endian integer and the buffer then copied directly. Both Numbers and Strings are treated
     * identically and are stored as UTF8 encoded Unicode, proceeded by the length of the encoded
     * string (in bytes) as a four-byte big-endian integer. Boolean is encoded as a single byte, 0
     * for <code>false</code> and 1 for <code>true</code> (and so has no Length parameter). The
     * Null tag ('\0') takes neither a Length nor a Value parameter.
     *
     * The tags 'L' and 'M' are for the document types List and Map respectively. These are encoded
     * recursively with the Length being the size of the collection. In the case of List, the value
     * is a Length number of marshalled AttributeValues. If the case of Map, the value is a Length
     * number of AttributeValue Pairs where the first must always have a String value.
     *
     * This implementation does <em>not</em> recognize loops. If an AttributeValue contains itself
     * (even indirectly) this code will recurse infinitely.
     *
     * @param attributeValue an AttributeValue instance
     * @return the serialized AttributeValue
     * @see java.io.DataInput
     */
    public static ByteBuffer marshall(final AttributeValue attributeValue) {
        try (ByteArrayOutputStream resultBytes = new ByteArrayOutputStream();
                DataOutputStream out = new DataOutputStream(resultBytes);) {
            marshall(attributeValue, out);
            out.close();
            resultBytes.close();
            return ByteBuffer.wrap(resultBytes.toByteArray());
        } catch (final IOException ex) {
            // Due to the objects in use, an IOException is not possible.
            throw new RuntimeException("Unexpected exception", ex);
        }
    }

    private static void marshall(final AttributeValue attributeValue, final DataOutputStream out)
            throws IOException {
        
        if (attributeValue.b() != null) {
            out.writeChar('b');
            writeBytes(attributeValue.b().asByteBuffer(), out);
        } else if (hasAttributeValueSet(attributeValue.bs())) {
            out.writeChar('B');
            writeBytesList(attributeValue.bs().stream()
                                         .map(BytesWrapper::asByteBuffer).collect(Collectors.toList()), out);
        } else if (attributeValue.n() != null) {
            out.writeChar('n');
            writeString(trimZeros(attributeValue.n()), out);
        } else if (hasAttributeValueSet(attributeValue.ns())) {
            out.writeChar('N');

            final List<String> ns = new ArrayList<>(attributeValue.ns().size());
            for (final String n : attributeValue.ns()) {
                ns.add(trimZeros(n));
            }
            writeStringList(ns, out);
        } else if (attributeValue.s() != null) {
            out.writeChar('s');
            writeString(attributeValue.s(), out);
        } else if (hasAttributeValueSet(attributeValue.ss())) {
            out.writeChar('S');
            writeStringList(attributeValue.ss(), out);
        } else if (attributeValue.bool() != null) {
            out.writeChar('?');
            out.writeByte((attributeValue.bool() ? TRUE_FLAG : FALSE_FLAG));
        } else if (Boolean.TRUE.equals(attributeValue.nul())) {
            out.writeChar('\0');
        } else if (hasAttributeValueSet(attributeValue.l())) {
            final List<AttributeValue> l = attributeValue.l();
            out.writeChar('L');
            out.writeInt(l.size());
            for (final AttributeValue attr : l) {
                if (attr == null) {
                    throw new NullPointerException(
                        "Encountered null list entry value while marshalling attribute value "
                        + attributeValue);
                }
                marshall(attr, out);
            }
        } else if (hasAttributeValueMap(attributeValue.m())) {
            final Map<String, AttributeValue> m = attributeValue.m();
            final List<String> mKeys = new ArrayList<>(m.keySet());
            Collections.sort(mKeys);
            out.writeChar('M');
            out.writeInt(m.size());
            for (final String mKey : mKeys) {
                marshall(AttributeValue.builder().s(mKey).build(), out);
                
                final AttributeValue mValue = m.get(mKey);
                
                if (mValue == null) {
                    throw new NullPointerException(
                        "Encountered null map value for key "
                        + mKey
                        + " while marshalling attribute value "
                        + attributeValue);
                }
                marshall(mValue, out);
            }
        } else {
            throw new IllegalArgumentException("A seemingly empty AttributeValue is indicative of invalid input or potential errors");
        }
    }

    /**
     * @see #marshall(AttributeValue)
     */
    public static AttributeValue unmarshall(final ByteBuffer plainText) {
        try (final DataInputStream in = new DataInputStream(
                new ByteBufferInputStream(plainText.asReadOnlyBuffer()))) {
            return unmarshall(in);
        } catch (IOException ex) {
            // Due to the objects in use, an IOException is not possible.
            throw new RuntimeException("Unexpected exception", ex);
        }
    }

    private static AttributeValue unmarshall(final DataInputStream in) throws IOException {
        char type = in.readChar();
        AttributeValue.Builder result = AttributeValue.builder();
        switch (type) {
        case '\0':
            result.nul(Boolean.TRUE);
            break;
        case 'b':
            result.b(SdkBytes.fromByteBuffer(readBytes(in)));
            break;
        case 'B':
            result.bs(readBytesList(in).stream().map(SdkBytes::fromByteBuffer).collect(Collectors.toList()));
            break;
        case 'n':
            result.n(readString(in));
            break;
        case 'N':
            result.ns(readStringList(in));
            break;
        case 's':
            result.s(readString(in));
            break;
        case 'S':
            result.ss(readStringList(in));
            break;
        case '?':
            final byte boolValue = in.readByte();

            if (boolValue == TRUE_FLAG) {
                result.bool(Boolean.TRUE);
            } else if (boolValue == FALSE_FLAG) {
                result.bool(Boolean.FALSE);
            } else {
                throw new IllegalArgumentException("Improperly formatted data");
            }
            break;
        case 'L':
            final int lCount = in.readInt();
            final List<AttributeValue> l = new ArrayList<>(lCount);
            for (int lIdx = 0; lIdx < lCount; lIdx++) {
                l.add(unmarshall(in));
            }
            result.l(l);
            break;
        case 'M':
            final int mCount = in.readInt();
            final Map<String, AttributeValue> m = new HashMap<>();
            for (int mIdx = 0; mIdx < mCount; mIdx++) {
                final AttributeValue key = unmarshall(in);
                if (key.s() == null) {
                    throw new IllegalArgumentException("Improperly formatted data");
                }
                AttributeValue value = unmarshall(in);
                m.put(key.s(), value);
            }
            result.m(m);
            break;
        default:
            throw new IllegalArgumentException("Unsupported data encoding");
        }

        return result.build();
    }

    private static String trimZeros(final String n) {
        BigDecimal number = new BigDecimal(n);
        if (number.compareTo(BigDecimal.ZERO) == 0) {
            return "0";
        }
        return number.stripTrailingZeros().toPlainString();
    }

    private static void writeStringList(List<String> values, final DataOutputStream out) throws IOException {
        final List<String> sorted = new ArrayList<>(values);
        Collections.sort(sorted);
        out.writeInt(sorted.size());
        for (final String v : sorted) {
            writeString(v, out);
        }
    }

    private static List<String> readStringList(final DataInputStream in) throws IOException,
            IllegalArgumentException {
        final int nCount = in.readInt();
        List<String> ns = new ArrayList<>(nCount);
        for (int nIdx = 0; nIdx < nCount; nIdx++) {
            ns.add(readString(in));
        }
        return ns;
    }

    private static void writeString(String value, final DataOutputStream out) throws IOException {
        final byte[] bytes = value.getBytes(UTF8);
        out.writeInt(bytes.length);
        out.write(bytes);
    }

    private static String readString(final DataInputStream in) throws IOException,
            IllegalArgumentException {
        byte[] bytes;
        int length;
        length = in.readInt();
        bytes = new byte[length];
        if(in.read(bytes) != length) {
            throw new IllegalArgumentException("Improperly formatted data");
        }
        return new String(bytes, UTF8);
    }

    private static void writeBytesList(List<ByteBuffer> values, final DataOutputStream out) throws IOException {
        final List<ByteBuffer> sorted = new ArrayList<>(values);
        Collections.sort(sorted);
        out.writeInt(sorted.size());
        for (final ByteBuffer v : sorted) {
            writeBytes(v, out);
        }
    }

    private static List<ByteBuffer> readBytesList(final DataInputStream in) throws IOException {
        final int bCount = in.readInt();
        List<ByteBuffer> bs = new ArrayList<>(bCount);
        for (int bIdx = 0; bIdx < bCount; bIdx++) {
            bs.add(readBytes(in));
        }
        return bs;
    }

    private static void writeBytes(ByteBuffer value, final DataOutputStream out) throws IOException {
        value = value.asReadOnlyBuffer();
        value.rewind();
        out.writeInt(value.remaining());
        while (value.hasRemaining()) {
            out.writeByte(value.get());
        }
    }

    private static ByteBuffer readBytes(final DataInputStream in) throws IOException {
        final int length = in.readInt();
        final byte[] buf = new byte[length];
        in.readFully(buf);
        return ByteBuffer.wrap(buf);
    }

    /**
     * Determines if the value of a 'set' type AttributeValue (various S types) has been explicitly set or not.
     * @param value the actual value portion of an AttributeValue of the appropriate type
     * @return true if the value of this type field has been explicitly set, false if it has not
     */
    private static boolean hasAttributeValueSet(Collection<?> value) {
        return value != null && value != DefaultSdkAutoConstructList.getInstance();
    }

    /**
     * Determines if the value of a 'map' type AttributeValue (M type) has been explicitly set or not.
     * @param value the actual value portion of a AttributeValue of the appropriate type
     * @return true if the value of this type field has been explicitly set, false if it has not
     */
    private static boolean hasAttributeValueMap(Map<?, ?> value) {
        return value != null && value != DefaultSdkAutoConstructMap.getInstance();
    }

}
