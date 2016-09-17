package org.cryptomator.cryptofs;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;

import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnit;
import org.mockito.junit.MockitoRule;

public class CryptoFileLockTest {

	@Rule
	public MockitoRule mockitoRule = MockitoJUnit.rule();

	@Rule
	public ExpectedException thrown = ExpectedException.none();

	private FileChannel channel = new DummyFileChannel();

	@Mock
	private FileLock delegate;

	private long size = 3728L;

	private long position = 323L;

	private boolean shared = true;

	private CryptoFileLock inTest;

	@Before
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
		thrown.expect(IllegalStateException.class);

		CryptoFileLock.builder() //
				.withDelegate(delegate) //
				.withPosition(position) //
				.withSize(size) //
				.thatIsShared(shared) //
				.build();
	}

	@Test
	public void testConstructionWithoutDelegateFails() {
		thrown.expect(IllegalStateException.class);

		CryptoFileLock.builder() //
				.withChannel(channel) //
				.withPosition(position) //
				.withSize(size) //
				.thatIsShared(shared) //
				.build();
	}

	@Test
	public void testConstructionWithoutPositionFails() {
		thrown.expect(IllegalStateException.class);

		CryptoFileLock.builder() //
				.withChannel(channel) //
				.withDelegate(delegate) //
				.withSize(size) //
				.thatIsShared(shared) //
				.build();
	}

	@Test
	public void testConstructionWithoutSizeFails() {
		thrown.expect(IllegalStateException.class);

		CryptoFileLock.builder() //
				.withChannel(channel) //
				.withDelegate(delegate) //
				.withPosition(position) //
				.thatIsShared(shared) //
				.build();
	}

	@Test
	public void testConstructionWithoutSharedFails() {
		thrown.expect(IllegalStateException.class);

		CryptoFileLock.builder() //
				.withChannel(channel) //
				.withDelegate(delegate) //
				.withPosition(position) //
				.withSize(size) //
				.build();
	}

	@Test
	public void testRelease() throws IOException {
		inTest.release();

		verify(delegate).release();
	}

	@Test
	public void testDelegate() {
		assertThat(inTest.delegate(), is(delegate));
	}

	@Test
	public void testIsValidWithValidDelegateAndOpenChannel() {
		when(delegate.isValid()).thenReturn(true);
		assertThat(inTest.isValid(), is(true));
	}

	@Test
	public void testIsValidWithValidDelegateAndClosedChannel() throws IOException {
		when(delegate.isValid()).thenReturn(true);
		channel.close();
		assertThat(inTest.isValid(), is(false));
	}

	@Test
	public void testIsValidWithInvalidDelegateAndOpenChannel() {
		when(delegate.isValid()).thenReturn(false);
		assertThat(inTest.isValid(), is(false));
	}

	@Test
	public void testIsValidWithInalidDelegateAndClosedChannel() throws IOException {
		when(delegate.isValid()).thenReturn(false);
		channel.close();
		assertThat(inTest.isValid(), is(false));
	}

	@Test
	public void testPosition() {
		assertThat(inTest.position(), is(position));
	}

	@Test
	public void testSize() {
		assertThat(inTest.size(), is(size));
	}

	@Test
	public void testChannel() {
		assertThat(inTest.channel(), is(channel));
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
		assertThat(inTest.isShared(), is(true));
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
		assertThat(inTest.isShared(), is(false));
	}

}
