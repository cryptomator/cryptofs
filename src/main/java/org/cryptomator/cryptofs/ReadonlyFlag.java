package org.cryptomator.cryptofs;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.ReadOnlyFileSystemException;

import javax.inject.Inject;

@PerFileSystem
class ReadonlyFlag {

	private static final Logger LOG = LoggerFactory.getLogger(ReadonlyFlag.class);

	private final boolean readonly;

	@Inject
	public ReadonlyFlag(CryptoFileSystemProperties properties, @PathToVault Path pathToVault) {
		if (properties.readonly()) {
			LOG.info("Vault opened readonly.");
			readonly = true;
		} else if (targetFileStoreIsReadonly(pathToVault)) {
			LOG.warn("Vault on readonly filesystem.");
			readonly = true;
		} else {
			LOG.debug("Vault opened for read and write.");
			readonly = false;
		}
	}

	private boolean targetFileStoreIsReadonly(Path pathToVault) {
		return UncheckedThrows //
				.rethrowUnchecked(IOException.class) //
				.from(() -> Files.getFileStore(pathToVault).isReadOnly());
	}

	public void assertWritable() throws ReadOnlyFileSystemException {
		if (readonly) {
			throw new ReadOnlyFileSystemException();
		}
	}

	public boolean isSet() {
		return readonly;
	}

}
