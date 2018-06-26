package org.cryptomator.cryptofs;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyZeroInteractions;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.nio.file.Path;

import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.mockito.junit.MockitoJUnit;
import org.mockito.junit.MockitoRule;

public class RootDirectoryInitializerTest {

	@Rule
	public MockitoRule mockitoRule = MockitoJUnit.rule();

	private final CryptoPathMapper cryptoPathMapper = mock(CryptoPathMapper.class);
	private final ReadonlyFlag readonlyFlag = mock(ReadonlyFlag.class);
	private final FilesWrapper filesWrapper = mock(FilesWrapper.class);

	private final CryptoPath cleartextRoot = mock(CryptoPath.class);
	private final Path ciphertextRoot = mock(Path.class);

	private RootDirectoryInitializer inTest = new RootDirectoryInitializer(cryptoPathMapper, readonlyFlag, filesWrapper);

	@Before
	public void setup() throws IOException {
		when(cryptoPathMapper.getCiphertextDirPath(cleartextRoot)).thenReturn(ciphertextRoot);
	}

	@Test
	public void testInitializeCreatesRootDirectoryIfReadonlyFlagIsNotSet() throws IOException {
		when(readonlyFlag.isSet()).thenReturn(false);

		UncheckedThrows.allowUncheckedThrowsOf(IOException.class).from(() -> inTest.initialize(cleartextRoot));

		verify(filesWrapper).createDirectories(ciphertextRoot);
	}

	@Test
	public void testInitializeDoesNotCreateRootDirectoryIfReadonlyFlagIsSet() throws IOException {
		when(readonlyFlag.isSet()).thenReturn(true);

		inTest.initialize(cleartextRoot);

		verifyZeroInteractions(filesWrapper);
	}

}
