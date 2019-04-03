package org.cryptomator.cryptofs;

import static java.lang.Math.max;

import java.util.concurrent.atomic.LongAdder;

import javax.inject.Inject;

/**
 * Provides access to file system performance metrics.
 * <p>
 * The available metrics are constantly updated in a thread-safe manner and can be polled at any time.
 */
@CryptoFileSystemScoped
public class CryptoFileSystemStats {

	private final LongAdder bytesRead = new LongAdder();
	private final LongAdder bytesWritten = new LongAdder();
	private final LongAdder bytesDecrypted = new LongAdder();
	private final LongAdder bytesEncrypted = new LongAdder();
	private final LongAdder chunkCacheAccesses = new LongAdder();
	private final LongAdder chunkCacheMisses = new LongAdder();
	private final LongAdder chunkCacheHits = new LongAdder();

	@Inject
	CryptoFileSystemStats() {
	}

	public long pollBytesRead() {
		return bytesRead.sumThenReset();
	}

	public void addBytesRead(long numBytes) {
		bytesRead.add(numBytes);
	}

	public long pollBytesWritten() {
		return bytesWritten.sumThenReset();
	}

	public void addBytesWritten(long numBytes) {
		bytesWritten.add(numBytes);
	}

	public long pollBytesDecrypted() {
		return bytesDecrypted.sumThenReset();
	}

	public void addBytesDecrypted(long numBytes) {
		bytesDecrypted.add(numBytes);
	}

	public long pollBytesEncrypted() {
		return bytesEncrypted.sumThenReset();
	}

	public void addBytesEncrypted(long numBytes) {
		bytesEncrypted.add(numBytes);
	}

	public long pollChunkCacheAccesses() {
		return chunkCacheAccesses.sumThenReset();
	}

	public void addChunkCacheAccess() {
		chunkCacheAccesses.increment();
		chunkCacheHits.increment();
	}

	public long pollChunkCacheHits() {
		return max(0, chunkCacheHits.sumThenReset());
	}

	public long pollChunkCacheMisses() {
		return chunkCacheMisses.sumThenReset();
	}

	public void addChunkCacheMiss() {
		chunkCacheMisses.increment();
		chunkCacheHits.decrement();
	}

}
