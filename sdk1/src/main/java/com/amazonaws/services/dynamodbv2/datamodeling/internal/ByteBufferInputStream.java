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

import java.io.InputStream;
import java.nio.ByteBuffer;

/**
 * @author Greg Rubin 
 */
public class ByteBufferInputStream extends InputStream {
    private final ByteBuffer buffer;

    public ByteBufferInputStream(ByteBuffer buffer) {
        this.buffer = buffer;
    }

    @Override
    public int read() {
        if (buffer.hasRemaining()) {
            int tmp = buffer.get();
            if (tmp < 0) {
                tmp += 256;
            }
            return tmp;
        } else {
            return -1;
        }
    }
    
    @Override
    public int read(byte[] b, int off, int len) {
        if (available() < len) {
            len = available();
        }
        buffer.get(b, off, len);
        return len;
    }
    
    @Override
    public int available() {
        return buffer.remaining();
    }
}
