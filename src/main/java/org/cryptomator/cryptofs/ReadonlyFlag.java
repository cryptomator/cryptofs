package org.cryptomator.cryptofs;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import javax.inject.Inject;

@PerFileSystem
class ReadonlyFlag {

	private final boolean value;

	@Inject
	public ReadonlyFlag(CryptoFileSystemProperties properties, @PathToVault Path pathToVault) {
		if (properties.readonly()) {
			value = true;
		} else {
			value = targetFileStoreIsReadonly(pathToVault);
		}
	}

	private boolean targetFileStoreIsReadonly(Path pathToVault) {
		return UncheckedThrows //
				.rethrowUnchecked(IOException.class) //
				.from(() -> Files.getFileStore(pathToVault).isReadOnly());
	}

	public boolean isSet() {
		return value;
	}

}
