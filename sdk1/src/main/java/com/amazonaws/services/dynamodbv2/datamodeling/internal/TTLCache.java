// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazonaws.services.dynamodbv2.datamodeling.internal;

import com.amazonaws.annotation.ThreadSafe;

import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.Function;

import static com.amazonaws.services.dynamodbv2.datamodeling.internal.Utils.checkNotNull;

/**
 * A cache, backed by an LRUCache, that uses a loader to calculate values on cache miss
 * or expired TTL.
 *
 * Note that this cache does not proactively evict expired entries,
 * however will immediately evict entries discovered to be expired on load.
 *
 * @param <T>
 *            value type
 */
@ThreadSafe
public final class TTLCache<T> {
    /**
     * Used for the internal cache.
     */
    private final LRUCache<LockedState<T>> cache;

    /**
     * Time to live for entries in the cache.
     */
    private final long ttlInNanos;

    /**
     * Used for loading new values into the cache on cache miss or expiration.
     */
    private final EntryLoader<T> defaultLoader;

    // Mockable time source, to allow us to test TTL behavior.
    // package access for tests
    MsClock clock = MsClock.WALLCLOCK;

    private static final long TTL_GRACE_IN_NANO = TimeUnit.MILLISECONDS.toNanos(500);

    /**
     * @param maxSize
     *            the maximum number of entries of the cache
     * @param ttlInMillis
     *            the time to live value for entries of the cache, in milliseconds
     */
    public TTLCache(final int maxSize, final long ttlInMillis, final EntryLoader<T> loader) {
        if (maxSize < 1) {
            throw new IllegalArgumentException("maxSize " + maxSize + " must be at least 1");
        }
        if (ttlInMillis < 1) {
            throw new IllegalArgumentException("ttlInMillis " + maxSize + " must be at least 1");
        }
        this.ttlInNanos = TimeUnit.MILLISECONDS.toNanos(ttlInMillis);
        this.cache = new LRUCache<>(maxSize);
        this.defaultLoader = checkNotNull(loader, "loader must not be null");
    }

    /**
     * Uses the default loader to calculate the value at key and insert it into the cache,
     * if it doesn't already exist or is expired according to the TTL.
     *
     * This immediately evicts entries past the TTL such that a load failure results
     * in the removal of the entry.
     *
     * Entries that are not expired according to the TTL are returned without recalculating the value.
     *
     * Within a grace period past the TTL, the cache may either return the cached value without recalculating
     * or use the loader to recalculate the value. This is implemented such that, in a multi-threaded environment,
     * only one thread per cache key uses the loader to recalculate the value at one time.
     *
     * @param key
     *         The cache key to load the value at
     * @return
     *         The value of the given value (already existing or re-calculated).
     */
    public T load(final String key) {
        return load(key, defaultLoader::load);
    }

    /**
     * Uses the inputted function to calculate the value at key and insert it into the cache,
     * if it doesn't already exist or is expired according to the TTL.
     *
     * This immediately evicts entries past the TTL such that a load failure results
     * in the removal of the entry.
     *
     * Entries that are not expired according to the TTL are returned without recalculating the value.
     *
     * Within a grace period past the TTL, the cache may either return the cached value without recalculating
     * or use the loader to recalculate the value. This is implemented such that, in a multi-threaded environment,
     * only one thread per cache key uses the loader to recalculate the value at one time.
     *
     * Returns the value of the given key (already existing or re-calculated).
     *
     * @param key
     *         The cache key to load the value at
     * @param f
     *         The function to use to load the value, given key as input
     * @return
     *         The value of the given value (already existing or re-calculated).
     */
    public T load(final String key, Function<String, T> f) {
        final LockedState<T> ls = cache.get(key);

        if (ls == null) {
            // The entry doesn't exist yet, so load a new one.
            return loadNewEntryIfAbsent(key, f);
        } else if (clock.timestampNano() - ls.getState().lastUpdatedNano > ttlInNanos + TTL_GRACE_IN_NANO) {
            // The data has expired past the grace period.
            // Evict the old entry and load a new entry.
            cache.remove(key);
            return loadNewEntryIfAbsent(key, f);
        } else if (clock.timestampNano() - ls.getState().lastUpdatedNano <= ttlInNanos) {
            // The data hasn't expired. Return as-is from the cache.
            return ls.getState().data;
        } else if (!ls.tryLock()) {
            // We are in the TTL grace period. If we couldn't grab the lock, then some other
            // thread is currently loading the new value. Because we are in the grace period,
            // use the cached data instead of waiting for the lock.
            return ls.getState().data;
        }

        // We are in the grace period and have acquired a lock.
        // Update the cache with the value determined by the loading function.
        try {
            T loadedData = f.apply(key);
            ls.update(loadedData, clock.timestampNano());
            return ls.getState().data;
        } finally {
            ls.unlock();
        }
    }

    // Synchronously calculate the value for a new entry in the cache if it doesn't already exist.
    // Otherwise return the cached value.
    // It is important that this is the only place where we use the loader for a new entry,
    // given that we don't have the entry yet to lock on.
    // This ensures that the loading function is only called once if multiple threads
    // attempt to add a new entry for the same key at the same time.
    private synchronized T loadNewEntryIfAbsent(final String key, Function<String, T> f) {
        // If the entry already exists in the cache, return it
        final LockedState<T> cachedState = cache.get(key);
        if (cachedState != null) {
           return cachedState.getState().data;
        }

        // Otherwise, load the data and create a new entry
        T loadedData = f.apply(key);
        LockedState<T> ls = new LockedState<>(loadedData, clock.timestampNano());
        cache.add(key, ls);
        return loadedData;
    }

    /**
     * Put a new entry in the cache.
     * Returns the value previously at that key in the cache,
     * or null if the entry previously didn't exist or
     * is expired.
     */
    public synchronized T put(final String key, final T value) {
        LockedState<T> ls = new LockedState<>(value, clock.timestampNano());
        LockedState<T> oldLockedState = cache.add(key, ls);
        if (oldLockedState == null || clock.timestampNano() - oldLockedState.getState().lastUpdatedNano > ttlInNanos + TTL_GRACE_IN_NANO) {
            return null;
        }
        return oldLockedState.getState().data;
    }

    /**
     * Get when the entry at this key was last updated.
     * Returns 0 if the entry doesn't exist at key.
     */
    public long getLastUpdated(String key) {
        LockedState<T> ls = cache.get(key);
        if (ls == null) {
            return 0;
        }
        return ls.getState().lastUpdatedNano;
    }

    /**
     * Returns the current size of the cache.
     */
    public int size() {
        return cache.size();
    }

    /**
     * Returns the maximum size of the cache.
     */
    public int getMaxSize() {
        return cache.getMaxSize();
    }

    /**
     * Clears all entries from the cache.
     */
    public void clear() {
        cache.clear();
    }

    @Override
    public String toString() {
        return cache.toString();
    }

    public interface EntryLoader<T> {
        T load(String entryKey);
    }

    // An object which stores a state alongside a lock,
    // and performs updates to that state atomically.
    // The state may only be updated if the lock is acquired by the current thread.
    private static class LockedState<T> {
        private final ReentrantLock lock = new ReentrantLock(true);
        private final AtomicReference<State<T>> state;

        public LockedState(T data, long createTimeNano) {
            state = new AtomicReference<>(new State<>(data, createTimeNano));
        }

        public State<T> getState() {
            return state.get();
        }

        public void unlock() {
            lock.unlock();
        }

        public boolean tryLock() {
            return lock.tryLock();
        }

        public void update(T data, long createTimeNano) {
            if (!lock.isHeldByCurrentThread()) {
                throw new IllegalStateException("Lock not held by current thread");
            }
            state.set(new State<>(data, createTimeNano));
        }
    }

    // An object that holds some data and the time at which this object was created
    private static class State<T> {
        public final T data;
        public final long lastUpdatedNano;

        public State(T data, long lastUpdatedNano) {
            this.data = data;
            this.lastUpdatedNano = lastUpdatedNano;
        }
    }
}
