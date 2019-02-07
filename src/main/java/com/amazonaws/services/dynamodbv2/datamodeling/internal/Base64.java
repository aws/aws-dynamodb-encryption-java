/*
 * Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

import java.util.Base64.Decoder;
import java.util.Base64.Encoder;

/**
 * A class for decoding Base64 strings and encoding bytes as Base64 strings.
 */
public class Base64 {
    private static final Decoder DECODER = java.util.Base64.getMimeDecoder();
    private static final Encoder ENCODER = java.util.Base64.getEncoder();

    private Base64() { }

    /**
     * Encode the bytes as a Base64 string.
     * <p>
     * See the Basic encoder in {@link java.util.Base64}
     */
    public static String encodeToString(byte[] bytes) {
        return ENCODER.encodeToString(bytes);
    }

    /**
     * Decode the Base64 string as bytes, ignoring illegal characters.
     * <p>
     * See the Mime Decoder in {@link java.util.Base64}
     */
    public static byte[] decode(String str) {
        if(str == null) {
            return null;
        }
        return DECODER.decode(str);
    }
}
