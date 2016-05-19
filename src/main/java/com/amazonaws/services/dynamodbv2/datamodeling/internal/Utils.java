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
