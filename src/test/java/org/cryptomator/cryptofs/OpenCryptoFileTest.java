package org.cryptomator.cryptofs;

import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.nio.channels.ClosedChannelException;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.util.concurrent.atomic.AtomicLong;

import org.cryptomator.cryptofs.OpenCounter.OpenState;
import org.cryptomator.cryptolib.api.Cryptor;
import org.cryptomator.cryptolib.api.FileHeader;
import org.junit.Rule;
import org.junit.Test;
import org.junit.experimental.theories.Theories;
import org.junit.experimental.theories.Theory;
import org.junit.rules.ExpectedException;
import org.junit.runner.RunWith;
import org.mockito.junit.MockitoJUnit;
import org.mockito.junit.MockitoRule;

@RunWith(Theories.class)
public class OpenCryptoFileTest {

	@Rule
	public MockitoRule mockitoRule = MockitoJUnit.rule();

	@Rule
	public ExpectedException thrown = ExpectedException.none();

	private EffectiveOpenOptions options = mock(EffectiveOpenOptions.class);
	private Cryptor cryptor = mock(Cryptor.class);
	private FileChannel channel = mock(FileChannel.class);
	private FileHeader header = mock(FileHeader.class);
	private ChunkCache chunkCache = mock(ChunkCache.class);
	private AtomicLong size = mock(AtomicLong.class);
	private Runnable onClose = mock(Runnable.class);
	private OpenCounter openCounter = mock(OpenCounter.class);
	private CryptoFileChannelFactory cryptoFileChannelFactory = mock(CryptoFileChannelFactory.class);
	private CryptoFileSystemStats stats = mock(CryptoFileSystemStats.class);

	private OpenCryptoFile inTest = new OpenCryptoFile(options, cryptor, channel, header, size, openCounter, cryptoFileChannelFactory, chunkCache, onClose, stats);

	@Theory
	public void testLockDelegatesToChannel(boolean shared) throws IOException {
		long position = 383872;
		long size = 48483;
		FileLock lock = mock(FileLock.class);
		when(channel.lock(position, size, shared)).thenReturn(lock);

		assertThat(inTest.lock(position, size, shared), is(lock));
	}

	@Theory
	public void testTryLockDelegatesToChannel(boolean shared) throws IOException {
		long position = 383872;
		long size = 48483;
		FileLock lock = mock(FileLock.class);
		when(channel.tryLock(position, size, shared)).thenReturn(lock);

		assertThat(inTest.tryLock(position, size, shared), is(lock));
	}

	@Test
	public void testOpenSucceedsIfOpenCounterReturnsJustOpened() throws IOException {
		when(openCounter.countOpen()).thenReturn(OpenState.JUST_OPENED);

		inTest.open(options);
	}

	@Test
	public void testOpenSucceedsIfOpenCounterReturnsWasOpenAndNotCreateNew() throws IOException {
		when(openCounter.countOpen()).thenReturn(OpenState.WAS_OPEN);
		when(options.createNew()).thenReturn(false);

		inTest.open(options);
	}

	@Test
	public void testOpenFailsIfOpenCounterReturnsWasOpenAndCreateNew() throws IOException {
		when(openCounter.countOpen()).thenReturn(OpenState.WAS_OPEN);
		when(options.createNew()).thenReturn(true);

		thrown.expect(IOException.class);
		thrown.expectMessage("File exists");

		inTest.open(options);
	}

	@Test
	public void testOpenFailsIfOpenCounterReturnsAlreadClosed() throws IOException {
		when(openCounter.countOpen()).thenReturn(OpenState.ALREADY_CLOSED);

		thrown.expect(ClosedChannelException.class);

		inTest.open(options);
	}

	@Test
	public void testCloseDelegatesToCryptoFileChannelFactory() throws IOException {
		inTest.close();

		verify(cryptoFileChannelFactory).close();
	}

}
