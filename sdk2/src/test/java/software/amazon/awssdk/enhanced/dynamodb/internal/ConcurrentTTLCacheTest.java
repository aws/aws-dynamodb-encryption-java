package software.amazon.awssdk.enhanced.dynamodb.internal;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import edu.umd.cs.mtc.MultithreadedTestCase;
import edu.umd.cs.mtc.TestFramework;
import java.util.concurrent.TimeUnit;
import org.testng.annotations.Test;

/* Test specific thread interleavings with behaviors we care about in the
 * TTLCache.
 */
public class ConcurrentTTLCacheTest {

  private static final long TTL_GRACE_IN_NANO = TimeUnit.MILLISECONDS.toNanos(500);
  private static final long ttlInMillis = 1000;

  @Test
  public void testGracePeriodCase() throws Throwable {
    TestFramework.runOnce(new GracePeriodCase());
  }

  @Test
  public void testExpiredCase() throws Throwable {
    TestFramework.runOnce(new ExpiredCase());
  }

  @Test
  public void testNewEntryCase() throws Throwable {
    TestFramework.runOnce(new NewEntryCase());
  }

  @Test
  public void testPutLoadCase() throws Throwable {
    TestFramework.runOnce(new PutLoadCase());
  }

  // Ensure the loader is only called once if two threads attempt to load during the grace period
  class GracePeriodCase extends MultithreadedTestCase {
    TTLCache<String> cache;
    TTLCache.EntryLoader loader;
    MsClock clock = mock(MsClock.class);

    @Override
    public void initialize() {
      loader =
          spy(
              new TTLCache.EntryLoader<String>() {
                @Override
                public String load(String entryKey) {
                  // Wait until thread2 finishes to complete load
                  waitForTick(2);
                  return "loadedValue";
                }
              });
      when(clock.timestampNano()).thenReturn((long) 0);
      cache = new TTLCache<>(3, ttlInMillis, loader);
      cache.clock = clock;

      // Put an initial value into the cache at time 0
      cache.put("k1", "v1");
    }

    // The thread that first calls load in the grace period and acquires the lock
    public void thread1() {
      when(clock.timestampNano()).thenReturn(TimeUnit.MILLISECONDS.toNanos(ttlInMillis) + 1);
      String loadedValue = cache.load("k1");
      assertTick(2);
      // Expect to get back the value calculated from load
      assertEquals("loadedValue", loadedValue);
    }

    // The thread that calls load in the grace period after the lock has been acquired
    public void thread2() {
      // Wait until the first thread acquires the lock and starts load
      waitForTick(1);
      when(clock.timestampNano()).thenReturn(TimeUnit.MILLISECONDS.toNanos(ttlInMillis) + 1);
      String loadedValue = cache.load("k1");
      // Expect to get back the original value in the cache
      assertEquals("v1", loadedValue);
    }

    @Override
    public void finish() {
      // Ensure the loader was only called once
      verify(loader, times(1)).load("k1");
    }
  }

  // Ensure the loader is only called once if two threads attempt to load an expired entry.
  class ExpiredCase extends MultithreadedTestCase {
    TTLCache<String> cache;
    TTLCache.EntryLoader loader;
    MsClock clock = mock(MsClock.class);

    @Override
    public void initialize() {
      loader =
          spy(
              new TTLCache.EntryLoader<String>() {
                @Override
                public String load(String entryKey) {
                  // Wait until thread2 is waiting for the lock to complete load
                  waitForTick(2);
                  return "loadedValue";
                }
              });
      when(clock.timestampNano()).thenReturn((long) 0);
      cache = new TTLCache<>(3, ttlInMillis, loader);
      cache.clock = clock;

      // Put an initial value into the cache at time 0
      cache.put("k1", "v1");
    }

    // The thread that first calls load after expiration
    public void thread1() {
      when(clock.timestampNano())
          .thenReturn(TimeUnit.MILLISECONDS.toNanos(ttlInMillis) + TTL_GRACE_IN_NANO + 1);
      String loadedValue = cache.load("k1");
      assertTick(2);
      // Expect to get back the value calculated from load
      assertEquals("loadedValue", loadedValue);
    }

    // The thread that calls load after expiration,
    // after the first thread calls load, but before
    // the new value is put into the cache.
    public void thread2() {
      // Wait until the first thread acquires the lock and starts load
      waitForTick(1);
      when(clock.timestampNano())
          .thenReturn(TimeUnit.MILLISECONDS.toNanos(ttlInMillis) + TTL_GRACE_IN_NANO + 1);
      String loadedValue = cache.load("k1");
      // Expect to get back the newly loaded value
      assertEquals("loadedValue", loadedValue);
      // assert that this thread only finishes once the first thread's load does
      assertTick(2);
    }

    @Override
    public void finish() {
      // Ensure the loader was only called once
      verify(loader, times(1)).load("k1");
    }
  }

  // Ensure the loader is only called once if two threads attempt to load the same new entry.
  class NewEntryCase extends MultithreadedTestCase {
    TTLCache<String> cache;
    TTLCache.EntryLoader loader;
    MsClock clock = mock(MsClock.class);

    @Override
    public void initialize() {
      loader =
          spy(
              new TTLCache.EntryLoader<String>() {
                @Override
                public String load(String entryKey) {
                  // Wait until thread2 is blocked to complete load
                  waitForTick(2);
                  return "loadedValue";
                }
              });
      when(clock.timestampNano()).thenReturn((long) 0);
      cache = new TTLCache<>(3, ttlInMillis, loader);
      cache.clock = clock;
    }

    // The thread that first calls load
    public void thread1() {
      String loadedValue = cache.load("k1");
      assertTick(2);
      // Expect to get back the value calculated from load
      assertEquals("loadedValue", loadedValue);
    }

    // The thread that calls load after the first thread calls load,
    // but before the new value is put into the cache.
    public void thread2() {
      // Wait until the first thread acquires the lock and starts load
      waitForTick(1);
      String loadedValue = cache.load("k1");
      // Expect to get back the newly loaded value
      assertEquals("loadedValue", loadedValue);
      // assert that this thread only finishes once the first thread's load does
      assertTick(2);
    }

    @Override
    public void finish() {
      // Ensure the loader was only called once
      verify(loader, times(1)).load("k1");
    }
  }

  // Ensure the loader blocks put on load/put of the same new entry
  class PutLoadCase extends MultithreadedTestCase {
    TTLCache<String> cache;
    TTLCache.EntryLoader loader;
    MsClock clock = mock(MsClock.class);

    @Override
    public void initialize() {
      loader =
          spy(
              new TTLCache.EntryLoader<String>() {
                @Override
                public String load(String entryKey) {
                  // Wait until the put blocks to complete load
                  waitForTick(2);
                  return "loadedValue";
                }
              });
      when(clock.timestampNano()).thenReturn((long) 0);
      cache = new TTLCache<>(3, ttlInMillis, loader);
      cache.clock = clock;
    }

    // The thread that first calls load
    public void thread1() {
      String loadedValue = cache.load("k1");
      // Expect to get back the value calculated from load
      assertEquals("loadedValue", loadedValue);
      verify(loader, times(1)).load("k1");
    }

    // The thread that calls put during the first thread's load
    public void thread2() {
      // Wait until the first thread is loading
      waitForTick(1);
      String previousValue = cache.put("k1", "v1");
      // Expect to get back the value loaded into the cache by thread1
      assertEquals("loadedValue", previousValue);
      // assert that this thread was blocked by the first thread
      assertTick(2);
    }
  }
}
