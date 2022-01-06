// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazonaws.services.dynamodbv2.datamodeling.internal;

import static org.testng.AssertJUnit.assertEquals;
import static org.testng.AssertJUnit.assertNull;
import static org.testng.AssertJUnit.assertTrue;

import org.testng.annotations.Test;

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
  public void testRemove() {
    final LRUCache<String> cache = new LRUCache<String>(3);
    assertEquals(0, cache.size());
    assertEquals(3, cache.getMaxSize());
    cache.add("k1", "v1");
    assertTrue(cache.size() == 1);
    final String oldValue = cache.remove("k1");
    assertTrue(cache.size() == 0);
    assertEquals("v1", oldValue);
    assertNull(cache.get("k1"));

    final String emptyValue = cache.remove("k1");
    assertTrue(cache.size() == 0);
    assertNull(emptyValue);
    assertNull(cache.get("k1"));
  }

  @Test
  public void testClear() {
    final LRUCache<String> cache = new LRUCache<String>(3);
    assertEquals(0, cache.size());
    cache.clear();
    assertEquals(0, cache.size());

    cache.add("k1", "v1");
    cache.add("k2", "v2");
    cache.add("k3", "v3");
    assertTrue(cache.size() == 3);
    cache.clear();
    assertTrue(cache.size() == 0);
    assertNull(cache.get("k1"));
    assertNull(cache.get("k2"));
    assertNull(cache.get("k3"));
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
