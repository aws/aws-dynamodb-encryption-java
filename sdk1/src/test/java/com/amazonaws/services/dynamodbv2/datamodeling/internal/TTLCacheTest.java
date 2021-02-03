// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazonaws.services.dynamodbv2.datamodeling.internal;

import org.testng.annotations.Test;

import java.util.concurrent.TimeUnit;
import java.util.function.Function;

import static org.mockito.Matchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertThrows;
import static org.testng.AssertJUnit.assertEquals;
import static org.testng.AssertJUnit.assertNull;
import static org.testng.AssertJUnit.assertTrue;

public class TTLCacheTest {

    private static final long TTL_GRACE_IN_NANO = TimeUnit.MILLISECONDS.toNanos(500);

    @Test(expectedExceptions = IllegalArgumentException.class)
    public void testInvalidSize() {
        final TTLCache<String> cache = new TTLCache<String>(0, 1000, mock(TTLCache.EntryLoader.class));
    }

    @Test(expectedExceptions = IllegalArgumentException.class)
    public void testInvalidTTL() {
        final TTLCache<String> cache = new TTLCache<String>(3, 0, mock(TTLCache.EntryLoader.class));
    }

    @Test(expectedExceptions = NullPointerException.class)
    public void testNullLoader() {
        final TTLCache<String> cache = new TTLCache<String>(3, 1000, null);
    }

    @Test
    public void testConstructor() {
        final TTLCache<String> cache = new TTLCache<String>(1000, 1000, mock(TTLCache.EntryLoader.class));
        assertEquals(0, cache.size());
        assertEquals(1000, cache.getMaxSize());
    }

    @Test
    public void testLoadPastMaxSize() {
        final String loadedValue = "loaded value";
        final long ttlInMillis = 1000;
        final int maxSize = 1;
        TTLCache.EntryLoader loader = spy(TTLCache.EntryLoader.class);
        when(loader.load(any())).thenReturn(loadedValue);
        MsClock clock = mock(MsClock.class);
        when(clock.timestampNano()).thenReturn((long) 0);

        final TTLCache<String> cache = new TTLCache<String>(maxSize, ttlInMillis, loader);
        cache.clock = clock;

        assertEquals(0, cache.size());
        assertEquals(maxSize, cache.getMaxSize());

        cache.load("k1");
        verify(loader, times(1)).load("k1");
        assertTrue(cache.size() == 1);

        String result = cache.load("k2");
        verify(loader, times(1)).load("k2");
        assertTrue(cache.size() == 1);
        assertEquals(loadedValue, result);

        // to verify result is in the cache, load one more time
        // and expect the loader to not be called
        String cachedValue = cache.load("k2");
        verifyNoMoreInteractions(loader);
        assertTrue(cache.size() == 1);
        assertEquals(loadedValue, cachedValue);
    }

    @Test
    public void testLoadNoExistingEntry() {
        final String loadedValue = "loaded value";
        final long ttlInMillis = 1000;
        final int maxSize = 3;
        TTLCache.EntryLoader loader = spy(TTLCache.EntryLoader.class);
        when(loader.load(any())).thenReturn(loadedValue);
        MsClock clock = mock(MsClock.class);
        when(clock.timestampNano()).thenReturn((long) 0);

        final TTLCache<String> cache = new TTLCache<String>(maxSize, ttlInMillis, loader);
        cache.clock = clock;

        assertEquals(0, cache.size());
        assertEquals(maxSize, cache.getMaxSize());

        String result = cache.load("k1");
        verify(loader, times(1)).load("k1");
        assertTrue(cache.size() == 1);
        assertEquals(loadedValue, result);

        // to verify result is in the cache, load one more time
        // and expect the loader to not be called
        String cachedValue = cache.load("k1");
        verifyNoMoreInteractions(loader);
        assertTrue(cache.size() == 1);
        assertEquals(loadedValue, cachedValue);
    }

    @Test
    public void testLoadNotExpired() {
        final String loadedValue = "loaded value";
        final long ttlInMillis = 1000;
        final int maxSize = 3;
        TTLCache.EntryLoader loader = spy(TTLCache.EntryLoader.class);
        when(loader.load(any())).thenReturn(loadedValue);
        MsClock clock = mock(MsClock.class);

        final TTLCache<String> cache = new TTLCache<String>(maxSize, ttlInMillis, loader);
        cache.clock = clock;

        assertEquals(0, cache.size());
        assertEquals(maxSize, cache.getMaxSize());

        // when first creating the entry, time is 0
        when(clock.timestampNano()).thenReturn((long) 0);
        cache.load("k1");
        assertTrue(cache.size() == 1);
        verify(loader, times(1)).load("k1");

        // on load, time is within TTL
        when(clock.timestampNano()).thenReturn(TimeUnit.MILLISECONDS.toNanos(ttlInMillis));
        String result = cache.load("k1");

        verifyNoMoreInteractions(loader);
        assertTrue(cache.size() == 1);
        assertEquals(loadedValue, result);
    }

    @Test
    public void testLoadInGrace() {
        final String loadedValue = "loaded value";
        final long ttlInMillis = 1000;
        final int maxSize = 3;
        TTLCache.EntryLoader loader = spy(TTLCache.EntryLoader.class);
        when(loader.load(any())).thenReturn(loadedValue);
        MsClock clock = mock(MsClock.class);

        final TTLCache<String> cache = new TTLCache<String>(maxSize, ttlInMillis, loader);
        cache.clock = clock;

        assertEquals(0, cache.size());
        assertEquals(maxSize, cache.getMaxSize());

        // when first creating the entry, time is zero
        when(clock.timestampNano()).thenReturn((long) 0);
        cache.load("k1");
        assertTrue(cache.size() == 1);
        verify(loader, times(1)).load("k1");

        // on load, time is past TTL but within the grace period
        when(clock.timestampNano()).thenReturn(TimeUnit.MILLISECONDS.toNanos(ttlInMillis) + 1);
        String result = cache.load("k1");

        // Because this is tested in a single thread,
        // this is expected to obtain the lock and load the new value
        verify(loader, times(2)).load("k1");
        verifyNoMoreInteractions(loader);
        assertTrue(cache.size() == 1);
        assertEquals(loadedValue, result);
    }

    @Test
    public void testLoadExpired() {
        final String loadedValue = "loaded value";
        final long ttlInMillis = 1000;
        final int maxSize = 3;
        TTLCache.EntryLoader loader = spy(TTLCache.EntryLoader.class);
        when(loader.load(any())).thenReturn(loadedValue);
        MsClock clock = mock(MsClock.class);

        final TTLCache<String> cache = new TTLCache<String>(maxSize, ttlInMillis, loader);
        cache.clock = clock;

        assertEquals(0, cache.size());
        assertEquals(maxSize, cache.getMaxSize());

        // when first creating the entry, time is zero
        when(clock.timestampNano()).thenReturn((long) 0);
        cache.load("k1");
        assertTrue(cache.size() == 1);
        verify(loader, times(1)).load("k1");

        // on load, time is past TTL and grace period
        when(clock.timestampNano()).thenReturn(TimeUnit.MILLISECONDS.toNanos(ttlInMillis) + TTL_GRACE_IN_NANO + 1);
        String result = cache.load("k1");

        verify(loader, times(2)).load("k1");
        verifyNoMoreInteractions(loader);
        assertTrue(cache.size() == 1);
        assertEquals(loadedValue, result);
    }

    @Test
    public void testLoadExpiredEviction() {
        final String loadedValue = "loaded value";
        final long ttlInMillis = 1000;
        final int maxSize = 3;
        TTLCache.EntryLoader loader = spy(TTLCache.EntryLoader.class);
        when(loader.load(any())).thenReturn(loadedValue).thenThrow(new IllegalStateException("This loader is mocked to throw a failure."));
        MsClock clock = mock(MsClock.class);

        final TTLCache<String> cache = new TTLCache<String>(maxSize, ttlInMillis, loader);
        cache.clock = clock;

        assertEquals(0, cache.size());
        assertEquals(maxSize, cache.getMaxSize());

        // when first creating the entry, time is zero
        when(clock.timestampNano()).thenReturn((long) 0);
        cache.load("k1");
        verify(loader, times(1)).load("k1");
        assertTrue(cache.size() == 1);

        // on load, time is past TTL and grace period
        when(clock.timestampNano()).thenReturn(TimeUnit.MILLISECONDS.toNanos(ttlInMillis) + TTL_GRACE_IN_NANO + 1);
        assertThrows(IllegalStateException.class, () -> cache.load("k1"));

        verify(loader, times(2)).load("k1");
        verifyNoMoreInteractions(loader);
        assertTrue(cache.size() == 0);
    }

    @Test
    public void testLoadWithFunction() {
        final String loadedValue = "loaded value";
        final String functionValue = "function value";
        final long ttlInMillis = 1000;
        final int maxSize = 3;
        final Function<String, String> function = spy(Function.class);
        when(function.apply(any())).thenReturn(functionValue);
        TTLCache.EntryLoader loader = spy(TTLCache.EntryLoader.class);
        when(loader.load(any())).thenReturn(loadedValue).thenThrow(new IllegalStateException("This loader is mocked to throw a failure."));
        MsClock clock = mock(MsClock.class);
        when(clock.timestampNano()).thenReturn((long) 0);

        final TTLCache<String> cache = new TTLCache<String>(maxSize, ttlInMillis, loader);
        cache.clock = clock;

        assertEquals(0, cache.size());
        assertEquals(maxSize, cache.getMaxSize());

        String result = cache.load("k1", function);
        verify(function, times(1)).apply("k1");
        assertTrue(cache.size() == 1);
        assertEquals(functionValue, result);

        // to verify result is in the cache, load one more time
        // and expect the loader to not be called
        String cachedValue = cache.load("k1");
        verifyNoMoreInteractions(function);
        verifyNoMoreInteractions(loader);
        assertTrue(cache.size() == 1);
        assertEquals(functionValue, cachedValue);
    }

    @Test
    public void testClear() {
        final String loadedValue = "loaded value";
        final long ttlInMillis = 1000;
        final int maxSize = 3;
        TTLCache.EntryLoader loader = spy(TTLCache.EntryLoader.class);
        when(loader.load(any())).thenReturn(loadedValue);

        final TTLCache<String> cache = new TTLCache<String>(maxSize, ttlInMillis, loader);

        assertTrue(cache.size() == 0);
        cache.load("k1");
        cache.load("k2");
        assertTrue(cache.size() == 2);

        cache.clear();
        assertTrue(cache.size() == 0);
    }

    @Test
    public void testPut() {
        final long ttlInMillis = 1000;
        final int maxSize = 3;
        TTLCache.EntryLoader loader = spy(TTLCache.EntryLoader.class);
        MsClock clock = mock(MsClock.class);
        when(clock.timestampNano()).thenReturn((long) 0);

        final TTLCache<String> cache = new TTLCache<String>(maxSize, ttlInMillis, loader);
        cache.clock = clock;

        assertEquals(0, cache.size());
        assertEquals(maxSize, cache.getMaxSize());

        String oldValue = cache.put("k1", "v1");
        assertNull(oldValue);
        assertTrue(cache.size() == 1);

        String oldValue2 = cache.put("k1", "v11");
        assertEquals("v1", oldValue2);
        assertTrue(cache.size() == 1);
    }

    @Test
    public void testExpiredPut() {
        final long ttlInMillis = 1000;
        final int maxSize = 3;
        TTLCache.EntryLoader loader = spy(TTLCache.EntryLoader.class);
        MsClock clock = mock(MsClock.class);
        when(clock.timestampNano()).thenReturn((long) 0);

        final TTLCache<String> cache = new TTLCache<String>(maxSize, ttlInMillis, loader);
        cache.clock = clock;

        assertEquals(0, cache.size());
        assertEquals(maxSize, cache.getMaxSize());

        // First put is at time 0
        String oldValue = cache.put("k1", "v1");
        assertNull(oldValue);
        assertTrue(cache.size() == 1);

        // Second put is at time past TTL and grace period
        when(clock.timestampNano()).thenReturn(TimeUnit.MILLISECONDS.toNanos(ttlInMillis) + TTL_GRACE_IN_NANO + 1);
        String oldValue2 = cache.put("k1", "v11");
        assertNull(oldValue2);
        assertTrue(cache.size() == 1);
    }

    @Test
    public void testPutPastMaxSize() {
        final String loadedValue = "loaded value";
        final long ttlInMillis = 1000;
        final int maxSize = 1;
        TTLCache.EntryLoader loader = spy(TTLCache.EntryLoader.class);
        when(loader.load(any())).thenReturn(loadedValue);
        MsClock clock = mock(MsClock.class);
        when(clock.timestampNano()).thenReturn((long) 0);

        final TTLCache<String> cache = new TTLCache<String>(maxSize, ttlInMillis, loader);
        cache.clock = clock;

        assertEquals(0, cache.size());
        assertEquals(maxSize, cache.getMaxSize());

        cache.put("k1", "v1");
        assertTrue(cache.size() == 1);

        cache.put("k2", "v2");
        assertTrue(cache.size() == 1);

        // to verify put value is in the cache, load
        // and expect the loader to not be called
        String cachedValue = cache.load("k2");
        verifyNoMoreInteractions(loader);
        assertTrue(cache.size() == 1);
        assertEquals(cachedValue, "v2");
    }
}
