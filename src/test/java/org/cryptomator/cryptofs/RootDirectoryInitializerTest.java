package org.cryptomator.cryptofs;

import org.cryptomator.cryptofs.CryptoPathMapper.CiphertextDirectory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.Path;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyZeroInteractions;
import static org.mockito.Mockito.when;

public class RootDirectoryInitializerTest {

	private final CryptoPathMapper cryptoPathMapper = mock(CryptoPathMapper.class);
	private final ReadonlyFlag readonlyFlag = mock(ReadonlyFlag.class);
	private final FilesWrapper filesWrapper = mock(FilesWrapper.class);

	private final CryptoPath cleartextRoot = mock(CryptoPath.class);
	private final Path ciphertextRoot = mock(Path.class);

	private RootDirectoryInitializer inTest = new RootDirectoryInitializer(cryptoPathMapper, readonlyFlag, filesWrapper);

	@BeforeEach
	public void setup() throws IOException {
		when(cryptoPathMapper.getCiphertextDir(cleartextRoot)).thenReturn(new CiphertextDirectory("", ciphertextRoot));
	}

	@Test
	public void testInitializeCreatesRootDirectoryIfReadonlyFlagIsNotSet() throws IOException {
		when(readonlyFlag.isSet()).thenReturn(false);

		inTest.initialize(cleartextRoot);

		verify(filesWrapper).createDirectories(ciphertextRoot);
	}

	@Test
	public void testInitializeDoesNotCreateRootDirectoryIfReadonlyFlagIsSet() throws IOException {
		when(readonlyFlag.isSet()).thenReturn(true);

		inTest.initialize(cleartextRoot);

		verifyZeroInteractions(filesWrapper);
	}

}
