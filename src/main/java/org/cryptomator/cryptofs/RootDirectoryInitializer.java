package org.cryptomator.cryptofs;

import static org.cryptomator.cryptofs.UncheckedThrows.rethrowUnchecked;

import java.io.IOException;
import java.nio.file.Path;

import javax.inject.Inject;

@PerFileSystem
class RootDirectoryInitializer {

	private final CryptoPathMapper cryptoPathMapper;
	private final ReadonlyFlag readonlyFlag;
	private final FilesWrapper files;

	@Inject
	public RootDirectoryInitializer(CryptoPathMapper cryptoPathMapper, ReadonlyFlag readonlyFlag, FilesWrapper files) {
		this.cryptoPathMapper = cryptoPathMapper;
		this.readonlyFlag = readonlyFlag;
		this.files = files;
	}

	public void initialize(CryptoPath cleartextRoot) {
		if (readonlyFlag.isSet()) {
			return;
		}
		rethrowUnchecked(IOException.class).from(() -> {
			Path ciphertextRoot = cryptoPathMapper.getCiphertextDirPath(cleartextRoot);
			files.createDirectories(ciphertextRoot);
		});
	}

}
