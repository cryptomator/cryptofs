package org.cryptomator.cryptofs;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class CryptoFileSystemStatsTest {

	private CryptoFileSystemStats inTest = new CryptoFileSystemStats();

	@Test
	public void testPollBytesRead() {
		Assertions.assertEquals(0l, inTest.pollBytesRead());

		inTest.addBytesRead(17L);
		Assertions.assertEquals(17l, inTest.pollBytesRead());

		inTest.addBytesRead(17L);
		inTest.addBytesRead(25L);
		Assertions.assertEquals(42l, inTest.pollBytesRead());
	}

	@Test
	public void testPollBytesWritten() {
		Assertions.assertEquals(0l, inTest.pollBytesWritten());

		inTest.addBytesWritten(17L);
		Assertions.assertEquals(17l, inTest.pollBytesWritten());

		inTest.addBytesWritten(17L);
		inTest.addBytesWritten(25L);
		Assertions.assertEquals(42l, inTest.pollBytesWritten());
	}

	@Test
	public void testPollBytesDecrypted() {
		Assertions.assertEquals(0l, inTest.pollBytesDecrypted());

		inTest.addBytesDecrypted(17L);
		Assertions.assertEquals(17l, inTest.pollBytesDecrypted());

		inTest.addBytesDecrypted(17L);
		inTest.addBytesDecrypted(25L);
		Assertions.assertEquals(42l, inTest.pollBytesDecrypted());
	}

	@Test
	public void testPollBytesEncrypted() {
		Assertions.assertEquals(0l, inTest.pollBytesEncrypted());

		inTest.addBytesEncrypted(17L);
		Assertions.assertEquals(17l, inTest.pollBytesEncrypted());

		inTest.addBytesEncrypted(17L);
		inTest.addBytesEncrypted(25L);
		Assertions.assertEquals(42l, inTest.pollBytesEncrypted());
	}

	@Test
	public void testPollChunkCacheAccesses() {
		Assertions.assertEquals(0l, inTest.pollChunkCacheAccesses());

		inTest.addChunkCacheAccess();
		Assertions.assertEquals(1l, inTest.pollChunkCacheAccesses());

		inTest.addChunkCacheAccess();
		inTest.addChunkCacheAccess();
		Assertions.assertEquals(2l, inTest.pollChunkCacheAccesses());
	}

	@Test
	public void testPollChunkCacheHits() {
		Assertions.assertEquals(0l, inTest.pollChunkCacheHits());

		inTest.addChunkCacheMiss();
		Assertions.assertEquals(0l, inTest.pollChunkCacheHits());

		inTest.addChunkCacheAccess();
		Assertions.assertEquals(1l, inTest.pollChunkCacheHits());

		inTest.addChunkCacheAccess();
		inTest.addChunkCacheMiss();
		inTest.addChunkCacheAccess();
		inTest.addChunkCacheAccess();
		inTest.addChunkCacheAccess();
		inTest.addChunkCacheMiss();
		Assertions.assertEquals(2l, inTest.pollChunkCacheHits());
	}

	@Test
	public void testPollChunkCacheMisses() {
		Assertions.assertEquals(0l, inTest.pollChunkCacheMisses());
		inTest.addChunkCacheMiss();
		Assertions.assertEquals(1l, inTest.pollChunkCacheMisses());

		inTest.addChunkCacheMiss();
		inTest.addChunkCacheMiss();
		Assertions.assertEquals(2l, inTest.pollChunkCacheMisses());
	}

}
