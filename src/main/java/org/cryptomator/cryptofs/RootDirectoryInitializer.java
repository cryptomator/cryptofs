package org.cryptomator.cryptofs;

import static org.cryptomator.cryptofs.UncheckedThrows.rethrowUnchecked;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import javax.inject.Inject;

@PerFileSystem
class RootDirectoryInitializer {

	private final CryptoPathMapper cryptoPathMapper;

	@Inject
	public RootDirectoryInitializer(CryptoPathMapper cryptoPathMapper) {
		this.cryptoPathMapper = cryptoPathMapper;
	}

	public void initialize(CryptoPath cleartextRoot) {
		rethrowUnchecked(IOException.class).from(() -> {
			Path ciphertextRoot = cryptoPathMapper.getCiphertextDirPath(cleartextRoot);
			Files.createDirectories(ciphertextRoot);
		});
	}

}
