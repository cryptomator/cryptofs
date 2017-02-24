package org.cryptomator.cryptofs;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;

import java.io.IOException;
import java.nio.file.ClosedFileSystemException;
import java.util.Iterator;

import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.mockito.junit.MockitoJUnit;
import org.mockito.junit.MockitoRule;

public class CryptoFileChannelFactoryTest {

	@Rule
	public MockitoRule mockitoRule = MockitoJUnit.rule();

	@Rule
	public ExpectedException thrown = ExpectedException.none();

	private final FinallyUtil finallyUtil = mock(FinallyUtil.class);

	private final CryptoFileChannelFactory inTest = new CryptoFileChannelFactory(finallyUtil);

	@SuppressWarnings("unchecked")

	@Before
	public void setup() {
		doAnswer(invocation -> {
			Iterator<RunnableThrowingException<?>> iterator = invocation.getArgument(0);
			while (iterator.hasNext()) {
				iterator.next().run();
			}
			return null;
		}).when(finallyUtil).guaranteeInvocationOf(any(Iterator.class));
	}

	@Test
	public void testCreateCreatesFileChannel() throws IOException {
		OpenCryptoFile openCryptoFile = mock(OpenCryptoFile.class);
		EffectiveOpenOptions options = mock(EffectiveOpenOptions.class);

		CryptoFileChannel channel = inTest.create(openCryptoFile, options);

		assertNotNull(channel);
	}

	@Test
	public void testCloseClosesAllNonClosedChannels() throws IOException {
		OpenCryptoFile openCryptoFile = mock(OpenCryptoFile.class);
		EffectiveOpenOptions options = mock(EffectiveOpenOptions.class);

		CryptoFileChannel channelA = inTest.create(openCryptoFile, options);
		CryptoFileChannel channelB = inTest.create(openCryptoFile, options);
		CryptoFileChannel channelC = inTest.create(openCryptoFile, options);

		channelB.close();

		assertThat(channelA.isOpen(), is(true));
		assertThat(channelB.isOpen(), is(false));
		assertThat(channelC.isOpen(), is(true));

		inTest.close();

		assertThat(channelA.isOpen(), is(false));
		assertThat(channelB.isOpen(), is(false));
		assertThat(channelC.isOpen(), is(false));
	}

	@Test
	public void testCreateAfterClosedThrowsClosedFileSystemException() throws IOException {
		OpenCryptoFile openCryptoFile = mock(OpenCryptoFile.class);
		EffectiveOpenOptions options = mock(EffectiveOpenOptions.class);

		thrown.expect(ClosedFileSystemException.class);

		inTest.close();
		inTest.create(openCryptoFile, options);
	}

}
