/*
 * Copyright 2015 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"). You may not use this file except
 * in compliance with the License. A copy of the License is located at
 *
 * http://aws.amazon.com/apache2.0
 *
 * or in the "license" file accompanying this file. This file is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */
package com.amazonaws.services.dynamodbv2.datamodeling.internal;

import org.testng.annotations.Test;

import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;

import static org.testng.AssertJUnit.assertEquals;
import static org.testng.AssertJUnit.assertNull;
import static org.testng.AssertJUnit.assertTrue;

public class LRUCacheTest {
    @Test
    public void test() {
        final LRUCache<String> cache = new LRUCache<String>(3);
        assertEquals(0, cache.size());
        assertEquals(3, cache.getMaxSize());
        cache.add("k1", "v1");
        assertTrue(cache.size() == 1);
        cache.add("k1", "v11");
        assertTrue(cache.size() == 1);
        cache.add("k2", "v2");
        assertTrue(cache.size() == 2);
        cache.add("k3", "v3");
        assertTrue(cache.size() == 3);
        assertEquals("v11", cache.get("k1"));
        assertEquals("v2", cache.get("k2"));
        assertEquals("v3", cache.get("k3"));
        cache.add("k4", "v4");
        assertTrue(cache.size() == 3);
        assertNull(cache.get("k1"));
        assertEquals("v4", cache.get("k4"));
        assertEquals("v2", cache.get("k2"));
        assertEquals("v3", cache.get("k3"));
        assertTrue(cache.size() == 3);
        cache.add("k5", "v5");
        assertNull(cache.get("k4"));
        assertEquals("v5", cache.get("k5"));
        assertEquals("v2", cache.get("k2"));
        assertEquals("v3", cache.get("k3"));
        cache.clear();
        assertEquals(0, cache.size());
    }

    @Test
    public void testListener() {
        final Map<String, String> removed = new HashMap<String, String>();
        final LRUCache<String> cache = new LRUCache<String>(3,
                new LRUCache.RemovalListener<String>() {
                    @Override
                    public void onRemoval(final Entry<String, String> entry) {
                        removed.put(entry.getKey(), entry.getValue());
                    }
                });
        assertTrue(cache.size() == 0);
        cache.add("k1", "v1");
        assertTrue(cache.size() == 1);
        cache.add("k1", "v11");
        assertTrue(cache.size() == 1);
        cache.add("k2", "v2");
        assertTrue(cache.size() == 2);
        cache.add("k3", "v3");
        assertTrue(cache.size() == 3);
        assertEquals("v11", cache.get("k1"));
        assertEquals("v2", cache.get("k2"));
        assertEquals("v3", cache.get("k3"));
        assertTrue(removed.isEmpty());
        cache.add("k4", "v4");
        assertTrue(cache.size() == 3);
        assertNull(cache.get("k1"));
        assertEquals(1, removed.size());
        assertEquals("v11", removed.get("k1"));
        removed.clear();
        assertEquals("v4", cache.get("k4"));
        assertEquals("v2", cache.get("k2"));
        assertEquals("v3", cache.get("k3"));
        assertTrue(cache.size() == 3);
        cache.add("k5", "v5");
        assertEquals(1, removed.size());
        assertEquals("v4", removed.get("k4"));
        removed.clear();
        assertNull(cache.get("k4"));
        assertEquals("v5", cache.get("k5"));
        assertEquals("v2", cache.get("k2"));
        assertEquals("v3", cache.get("k3"));
        cache.clear();
        assertEquals(0, cache.size());
        assertEquals(3, removed.size());
        assertEquals("v5", removed.get("k5"));
        assertEquals("v2", removed.get("k2"));
        assertEquals("v3", removed.get("k3"));
    }

    @Test(expectedExceptions = IllegalArgumentException.class)
    public void testZeroSize() {
        new LRUCache<Object>(0);
    }

    @Test(expectedExceptions = IllegalArgumentException.class)
    public void testIllegalArgument() {
        new LRUCache<Object>(-1);
    }

    @Test
    public void testSingleEntry() {
        final LRUCache<String> cache = new LRUCache<String>(1);
        assertTrue(cache.size() == 0);
        cache.add("k1", "v1");
        assertTrue(cache.size() == 1);
        cache.add("k1", "v11");
        assertTrue(cache.size() == 1);
        assertEquals("v11", cache.get("k1"));

        cache.add("k2", "v2");
        assertTrue(cache.size() == 1);
        assertEquals("v2", cache.get("k2"));
        assertNull(cache.get("k1"));

        cache.add("k3", "v3");
        assertTrue(cache.size() == 1);
        assertEquals("v3", cache.get("k3"));
        assertNull(cache.get("k2"));
    }

}
