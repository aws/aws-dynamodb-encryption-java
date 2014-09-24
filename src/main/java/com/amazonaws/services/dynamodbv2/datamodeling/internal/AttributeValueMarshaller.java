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

import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.math.BigDecimal;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import com.amazonaws.services.dynamodbv2.model.AttributeValue;

public class AttributeValueMarshaller {
    private static final Charset UTF8 = Charset.forName("UTF-8");
    /**
     * Marshalls the data using a TLV (Tag-Length-Value) encoding. The tag may be
     * 'b', 'n', or 's' to represent a ByteBuffer, Number, or String
     * respectively. The tag may also be capitalized to represent an array of
     * that type. If an array is stored, then a four-byte big-endian integer is
     * written representing the number of array elements. If a ByteBuffer is
     * stored, the length of the buffer is stored as a four-byte big-endian
     * integer and the buffer then copied directly. Both Numbers and Strings are
     * treated identically and are stored as UTF8 encoded Unicode, proceeded by
     * the length of the encoded string (in bytes) as a four-byte big-endian
     * integer.
     *
     * @param attributeValue
     * @return the serialized AttributeValue
     * @see java.io.DataInput
     */
    public static ByteBuffer marshall(AttributeValue attributeValue) {
        try {
            ByteArrayOutputStream resultBytes = new ByteArrayOutputStream();
            DataOutputStream out = new DataOutputStream(resultBytes);
            byte[] bytes;
            
            if (attributeValue.getB() != null) {
                ByteBuffer input = attributeValue.getB();
                input.rewind();
                out.writeChar('b');
                out.writeInt(input.remaining());
                while (input.hasRemaining()) {
                    out.writeByte(input.get());
                }
                input.rewind();
            } else if (attributeValue.getBS() != null) {
                List<ByteBuffer> bs = new ArrayList<ByteBuffer>(attributeValue.getBS());
                Collections.sort(bs);
                out.writeChar('B');
                out.writeInt(bs.size());
                for (ByteBuffer b : bs) {
                    b.rewind();
                    out.writeInt(b.remaining());
                    while (b.hasRemaining()) {
                        out.writeByte(b.get());
                    }
                    b.rewind();
                }
            } else if (attributeValue.getN() != null) {
                String n = trimZeros(attributeValue.getN());
                bytes = n.getBytes(UTF8);
                out.writeChar('n');
                out.writeInt(bytes.length);
                out.write(bytes);
            } else if (attributeValue.getNS() != null) {
                List<String> ns = new ArrayList<String>(attributeValue.getNS().size());
                for (String n : attributeValue.getNS()) {
                    ns.add(trimZeros(n));
                }
                Collections.sort(ns);
                out.writeChar('N');
                out.writeInt(ns.size());
                for (String n : ns) {
                    bytes = n.getBytes(UTF8);
                    out.writeInt(bytes.length);
                    out.write(bytes);
                }
            } else if (attributeValue.getS() != null) {
                out.writeChar('s');
                bytes = attributeValue.getS().getBytes(UTF8);
                out.writeInt(bytes.length);
                out.write(bytes);
            } else if (attributeValue.getSS() != null) {
                List<String> ss = new ArrayList<String>(attributeValue.getSS());
                Collections.sort(ss);
                out.writeChar('S');
                out.writeInt(ss.size());
                for (String s : ss) {
                    bytes = s.getBytes(UTF8);
                    out.writeInt(bytes.length);
                    out.write(bytes);
                }
            } else {
                out.writeChar('\0');
            }
            out.close();
            return ByteBuffer.wrap(resultBytes.toByteArray());
        } catch (IOException ex) {
            // Due to the objects in use, an IOException is not possible.
            throw new RuntimeException("Unexpected exception", ex);
        }
    }

    private static String trimZeros(final String n) {
        BigDecimal number = new BigDecimal(n);
        if (number.compareTo(BigDecimal.ZERO) == 0)
            return "0";
        return number.stripTrailingZeros().toPlainString();
    }

    /**
     * @see #marshall(AttributeValue)
     */
    public static AttributeValue unmarshall(ByteBuffer plainText) {
        plainText.mark();
        try (DataInputStream in = new DataInputStream(new ByteBufferInputStream(plainText))) {
            byte[] bytes;
            int length;

            char type = in.readChar();
            AttributeValue result = new AttributeValue();
            ByteBuffer b;
            switch (type) {
            case '\0':
                break;
            case 'b':
                length = in.readInt();
                b = ByteBuffer.allocate(length);
                for (int x = 0; x < length; x++) {
                    b.put(in.readByte());
                }
                b.rewind();
                result.setB(b);
                break;
            case 'B':
                final int bCount = in.readInt();
                List<ByteBuffer> bs = new ArrayList<ByteBuffer>(bCount);
                for (int bIdx = 0; bIdx < bCount; bIdx++) {
                    int bLength = in.readInt();
                    b = ByteBuffer.allocate(bLength);
                    for (int x = 0; x < bLength; x++) {
                        b.put(in.readByte());
                    }
                    b.rewind();
                    bs.add(b);
                }
                result.setBS(bs);
                break;
            case 'n':
                length = in.readInt();
                bytes = new byte[length];
                if(in.read(bytes) != length) {
                    throw new IllegalArgumentException("Improperly formatted data");
                }
                result.setN(new String(bytes, UTF8));
                break;
            case 'N':
                final int nCount = in.readInt();
                List<String> ns = new ArrayList<String>(nCount);
                for (int nIdx = 0; nIdx < nCount; nIdx++) {
                    length = in.readInt();
                    bytes = new byte[length];
                    if (in.read(bytes) != length) {
                        throw new IllegalArgumentException("Improperly formatted data");
                    }
                    ns.add(new String(bytes, UTF8));
                }
                result.setNS(ns);
                break;
            case 's':
                length = in.readInt();
                bytes = new byte[length];
                if (in.read(bytes) != length) {
                    throw new IllegalArgumentException("Improperly formatted data");
                }
                result.setS(new String(bytes, UTF8));
                break;
            case 'S':
                final int sCount = in.readInt();
                List<String> ss = new ArrayList<String>(sCount);
                for (int sIdx = 0; sIdx < sCount; sIdx++) {
                    length = in.readInt();
                    bytes = new byte[length];
                    if (in.read(bytes) != length) {
                        throw new IllegalArgumentException("Improperly formatted data");
                    }
                    ss.add(new String(bytes, UTF8));
                }
                result.setSS(ss);
                break;
            default:
                throw new IllegalArgumentException("Unsupported data encoding");
            }

            return result;
        } catch (IOException ex) {
            // Due to the objects in use, an IOException is not possible.
            throw new RuntimeException("Unexpected exception", ex);
        } finally {
            plainText.reset();
        }
    }
}
