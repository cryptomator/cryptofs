package org.cryptomator.cryptofs;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.io.IOException;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;

import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class CryptoFileLockTest {

	private FileChannel channel = new DummyFileChannel();

	private FileLock delegate = Mockito.mock(FileLock.class);

	private long size = 3728l;

	private long position = 323l;

	private boolean shared = true;

	private CryptoFileLock inTest;

	@BeforeEach
	public void setup() {
		inTest = CryptoFileLock.builder() //
				.withChannel(channel) //
				.withDelegate(delegate) //
				.withPosition(position) //
				.withSize(size) //
				.thatIsShared(shared) //
				.build();
	}

	@Test
	public void testConstructionWithoutChannelFails() {
		Assertions.assertThrows(IllegalStateException.class, () -> {
			CryptoFileLock.builder() //
					.withDelegate(delegate) //
					.withPosition(position) //
					.withSize(size) //
					.thatIsShared(shared) //
					.build();
		});
	}

	@Test
	public void testConstructionWithoutDelegateFails() {
		Assertions.assertThrows(IllegalStateException.class, () -> {
			CryptoFileLock.builder() //
					.withChannel(channel) //
					.withPosition(position) //
					.withSize(size) //
					.thatIsShared(shared) //
					.build();
		});
	}

	@Test
	public void testConstructionWithoutPositionFails() {
		Assertions.assertThrows(IllegalStateException.class, () -> {
			CryptoFileLock.builder() //
					.withChannel(channel) //
					.withDelegate(delegate) //
					.withSize(size) //
					.thatIsShared(shared) //
					.build();
		});
	}

	@Test
	public void testConstructionWithoutSizeFails() {
		Assertions.assertThrows(IllegalStateException.class, () -> {
			CryptoFileLock.builder() //
					.withChannel(channel) //
					.withDelegate(delegate) //
					.withPosition(position) //
					.thatIsShared(shared) //
					.build();
		});
	}

	@Test
	public void testConstructionWithoutSharedFails() {
		Assertions.assertThrows(IllegalStateException.class, () -> {
			CryptoFileLock.builder() //
					.withChannel(channel) //
					.withDelegate(delegate) //
					.withPosition(position) //
					.withSize(size) //
					.build();
		});
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
		CryptoFileLock inTest = CryptoFileLock.builder() //
				.withChannel(channel) //
				.withDelegate(delegate) //
				.withPosition(position) //
				.withSize(size) //
				.thatIsShared(true) //
				.build();
		Assertions.assertTrue(inTest.isShared());
	}

	@Test
	public void testSharedFalse() {
		CryptoFileLock inTest = CryptoFileLock.builder() //
				.withChannel(channel) //
				.withDelegate(delegate) //
				.withPosition(position) //
				.withSize(size) //
				.thatIsShared(false) //
				.build();
		Assertions.assertFalse(inTest.isShared());
	}

}
