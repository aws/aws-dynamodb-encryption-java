// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazonaws.services.dynamodbv2.datamodeling.internal;

import com.amazonaws.annotation.ThreadSafe;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Map.Entry;

/**
 * A bounded cache that has a LRU eviction policy when the cache is full.
 *
 * @param <T>
 *            value type
 */
@ThreadSafe
public final class LRUCache<T> {
    /**
     * Used for the internal cache.
     */
    private final Map<String, T> map;

    /**
     * Maximum size of the cache.
     */
    private final int maxSize;

    /**
     * @param maxSize
     *            the maximum number of entries of the cache
     */
    public LRUCache(final int maxSize) {
        if (maxSize < 1) {
            throw new IllegalArgumentException("maxSize " + maxSize + " must be at least 1");
        }
        this.maxSize = maxSize;
        map = Collections.synchronizedMap(new LRUHashMap<>(maxSize));
    }

    /**
     * Adds an entry to the cache, evicting the earliest entry if necessary.
     */
    public T add(final String key, final T value) {
        return map.put(key, value);
    }

    /** Returns the value of the given key; or null of no such entry exists. */
    public T get(final String key) {
        return map.get(key);
    }

    /**
     * Returns the current size of the cache.
     */
    public int size() {
        return map.size();
    }

    /**
     * Returns the maximum size of the cache.
     */
    public int getMaxSize() {
        return maxSize;
    }

    public void clear() {
        map.clear();
    }

    public T remove(String key) {
        return map.remove(key);
    }

    @Override
    public String toString() {
        return map.toString();
    }

    @SuppressWarnings("serial")
    private static class LRUHashMap<T> extends LinkedHashMap<String, T> {
        private final int maxSize;

        private LRUHashMap(final int maxSize) {
            super(10, 0.75F, true);
            this.maxSize = maxSize;
        }

        @Override
        protected boolean removeEldestEntry(final Entry<String, T> eldest) {
            return size() > maxSize;
        }
    }
}
