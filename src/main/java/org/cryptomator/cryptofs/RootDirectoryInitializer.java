package org.cryptomator.cryptofs;

import javax.inject.Inject;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Path;

@CryptoFileSystemScoped
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
		try {
			Path ciphertextRoot = cryptoPathMapper.getCiphertextDir(cleartextRoot).path;
			files.createDirectories(ciphertextRoot);
		} catch (IOException e) {
			throw new UncheckedIOException(e);
		}
	}

}
