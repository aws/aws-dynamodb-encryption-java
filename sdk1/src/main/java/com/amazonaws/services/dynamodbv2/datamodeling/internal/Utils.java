/*
 * Copyright 2016 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

import java.security.SecureRandom;

public class Utils {
    private static final ThreadLocal<SecureRandom> RND = new ThreadLocal<SecureRandom>() {
        @Override
        protected SecureRandom initialValue() {
            final SecureRandom result = new SecureRandom();
            result.nextBoolean(); // Force seeding
            return result;
        }
    };

    private Utils() {
        // Prevent instantiation
    }

    public static SecureRandom getRng() {
        return RND.get();
    }

    public static byte[] getRandom(int len) {
        final byte[] result = new byte[len];
        getRng().nextBytes(result);
        return result;
    }
}
