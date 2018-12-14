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

import org.testng.annotations.Test;

import java.io.IOException;
import java.nio.ByteBuffer;

import static org.testng.AssertJUnit.assertArrayEquals;
import static org.testng.AssertJUnit.assertEquals;
import static org.testng.AssertJUnit.assertFalse;

public class ByteBufferInputStreamTest {

    @Test
    public void testRead() throws IOException {
        ByteBufferInputStream bis = new ByteBufferInputStream(ByteBuffer.wrap(new byte[]{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}));
        for (int x = 0; x < 10; ++x) {
            assertEquals(10 - x, bis.available());
            assertEquals(x, bis.read());
        }
        assertEquals(0, bis.available());
        bis.close();
    }

    @Test
    public void testReadByteArray() throws IOException {
        ByteBufferInputStream bis = new ByteBufferInputStream(ByteBuffer.wrap(new byte[]{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}));
        assertEquals(10, bis.available());

        byte[] buff = new byte[4];

        int len = bis.read(buff);
        assertEquals(4, len);
        assertEquals(6, bis.available());
        assertArrayEquals(new byte[]{0, 1, 2, 3}, buff);

        len = bis.read(buff);
        assertEquals(4, len);
        assertEquals(2, bis.available());
        assertArrayEquals(new byte[]{4, 5, 6, 7}, buff);

        len = bis.read(buff);
        assertEquals(2, len);
        assertEquals(0, bis.available());
        assertArrayEquals(new byte[]{8, 9, 6, 7}, buff);
        bis.close();
    }

    @Test
    public void testSkip() throws IOException {
        ByteBufferInputStream bis = new ByteBufferInputStream(ByteBuffer.wrap(new byte[]{(byte) 0xFA, 15, 15, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9}));
        assertEquals(13, bis.available());
        assertEquals(0xFA, bis.read());
        assertEquals(12, bis.available());
        bis.skip(2);
        assertEquals(10, bis.available());
        for (int x = 0; x < 10; ++x) {
            assertEquals(x, bis.read());
        }
        assertEquals(0, bis.available());
        assertEquals(-1, bis.read());
        bis.close();
    }

    @Test
    public void testMarkSupported() throws IOException {
        try (ByteBufferInputStream bis = new ByteBufferInputStream(ByteBuffer.allocate(0))) {
            assertFalse(bis.markSupported());
        }
    }
}
