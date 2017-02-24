package org.cryptomator.cryptofs;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;

import org.junit.Test;

public class CryptoFileSystemStatsTest {

	private CryptoFileSystemStats inTest = new CryptoFileSystemStats();

	@Test
	public void testPollBytesRead() {
		assertThat(inTest.pollBytesRead(), is(0L));

		inTest.addBytesRead(17L);

		assertThat(inTest.pollBytesRead(), is(17L));

		inTest.addBytesRead(17L);
		inTest.addBytesRead(25L);

		assertThat(inTest.pollBytesRead(), is(42L));
	}

	@Test
	public void testPollBytesWritten() {
		assertThat(inTest.pollBytesWritten(), is(0L));

		inTest.addBytesWritten(17L);

		assertThat(inTest.pollBytesWritten(), is(17L));

		inTest.addBytesWritten(17L);
		inTest.addBytesWritten(25L);

		assertThat(inTest.pollBytesWritten(), is(42L));
	}

	@Test
	public void testPollBytesDecrypted() {
		assertThat(inTest.pollBytesDecrypted(), is(0L));

		inTest.addBytesDecrypted(17L);

		assertThat(inTest.pollBytesDecrypted(), is(17L));

		inTest.addBytesDecrypted(17L);
		inTest.addBytesDecrypted(25L);

		assertThat(inTest.pollBytesDecrypted(), is(42L));
	}

	@Test
	public void testPollBytesEncrypted() {
		assertThat(inTest.pollBytesEncrypted(), is(0L));

		inTest.addBytesEncrypted(17L);

		assertThat(inTest.pollBytesEncrypted(), is(17L));

		inTest.addBytesEncrypted(17L);
		inTest.addBytesEncrypted(25L);

		assertThat(inTest.pollBytesEncrypted(), is(42L));
	}

	@Test
	public void testPollChunkCacheAccesses() {
		assertThat(inTest.pollChunkCacheAccesses(), is(0L));

		inTest.addChunkCacheAccess();

		assertThat(inTest.pollChunkCacheAccesses(), is(1L));

		inTest.addChunkCacheAccess();
		inTest.addChunkCacheAccess();

		assertThat(inTest.pollChunkCacheAccesses(), is(2L));
	}

	@Test
	public void testPollChunkCacheHits() {
		assertThat(inTest.pollChunkCacheHits(), is(0L));

		inTest.addChunkCacheMiss();

		assertThat(inTest.pollChunkCacheHits(), is(0L));

		inTest.addChunkCacheAccess();

		assertThat(inTest.pollChunkCacheHits(), is(1L));

		inTest.addChunkCacheAccess();
		inTest.addChunkCacheMiss();
		inTest.addChunkCacheAccess();
		inTest.addChunkCacheAccess();
		inTest.addChunkCacheAccess();
		inTest.addChunkCacheMiss();

		assertThat(inTest.pollChunkCacheHits(), is(2L));
	}

	@Test
	public void testPollChunkCacheMisses() {
		assertThat(inTest.pollChunkCacheMisses(), is(0L));

		inTest.addChunkCacheMiss();

		assertThat(inTest.pollChunkCacheMisses(), is(1L));

		inTest.addChunkCacheMiss();
		inTest.addChunkCacheMiss();

		assertThat(inTest.pollChunkCacheMisses(), is(2L));
	}

}
