package org.cryptomator.cryptofs;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import javax.inject.Inject;

@PerFileSystem
class ReadonlyFlag {

	private final boolean value;

	private final String notWritableError;

	@Inject
	public ReadonlyFlag(CryptoFileSystemProperties properties, @PathToVault Path pathToVault) {
		if (properties.readonly()) {
			value = true;
			notWritableError = "Vault opened readonly";
		} else {
			value = targetFileStoreIsReadonly(pathToVault);
			if (value) {
				notWritableError = "Vault on readonly filesystem";
			} else {
				notWritableError = null;
			}
		}
	}

	private boolean targetFileStoreIsReadonly(Path pathToVault) {
		return UncheckedThrows //
				.rethrowUnchecked(IOException.class) //
				.from(() -> Files.getFileStore(pathToVault).isReadOnly());
	}

	public void assertWritable() throws IOException {
		if (notWritableError != null) {
			throw new IOException(notWritableError);
		}
	}

	public boolean isSet() {
		return value;
	}

}
