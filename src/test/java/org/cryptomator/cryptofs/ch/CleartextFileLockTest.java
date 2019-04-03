package org.cryptomator.cryptofs.ch;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.io.IOException;
import java.nio.channels.FileLock;

import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class CleartextFileLockTest {

	private CleartextFileChannel channel = Mockito.mock(CleartextFileChannel.class);
	private FileLock delegate = Mockito.mock(FileLock.class);
	private long size = 3728l;
	private long position = 323l;
	private boolean shared = true;
	private CleartextFileLock inTest;

	@BeforeEach
	public void setup() {
		inTest = new CleartextFileLock(channel, delegate, position, size, shared);
	}

	@Test
	public void testRelease() throws IOException {
		inTest.release();

		verify(delegate).release();
	}

	@Test
	public void testDelegate() {
		Assertions.assertSame(delegate, inTest.delegate());
	}

	@Test
	public void testIsValidWithValidDelegateAndOpenChannel() {
		when(delegate.isValid()).thenReturn(true);
		Assertions.assertTrue(inTest.isValid());
	}

	@Disabled // TODO: invalidate locks when closing channel
	@Test
	public void testIsValidWithValidDelegateAndClosedChannel() throws IOException {
		when(delegate.isValid()).thenReturn(true);
		channel.close();
		Assertions.assertFalse(inTest.isValid());
	}

	@Test
	public void testIsValidWithInvalidDelegateAndOpenChannel() {
		when(delegate.isValid()).thenReturn(false);
		Assertions.assertFalse(inTest.isValid());
	}

	@Disabled // TODO: invalidate locks when closing channel
	@Test
	public void testIsValidWithInalidDelegateAndClosedChannel() throws IOException {
		when(delegate.isValid()).thenReturn(false);
		channel.close();
		Assertions.assertFalse(inTest.isValid());
	}

	@Test
	public void testPosition() {
		Assertions.assertEquals(position, inTest.position());
	}

	@Test
	public void testSize() {
		Assertions.assertEquals(size, inTest.size());
	}

	@Test
	public void testChannel() {
		Assertions.assertSame(channel, inTest.channel());
	}

	@Test
	public void testSharedTrue() {
		CleartextFileLock inTest = new CleartextFileLock(channel, delegate, position, size, true);
		Assertions.assertTrue(inTest.isShared());
	}

	@Test
	public void testSharedFalse() {
		CleartextFileLock inTest = new CleartextFileLock(channel, delegate, position, size, false);
		Assertions.assertFalse(inTest.isShared());
	}

}
