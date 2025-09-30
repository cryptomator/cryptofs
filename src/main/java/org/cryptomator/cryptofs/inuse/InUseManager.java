package org.cryptomator.cryptofs.inuse;

import java.nio.file.Path;

public interface InUseManager {

	default boolean isInUseByOthers(Path ciphertextPath) {
		return false;
	}

	default UseToken use(Path ciphertextPath) throws FileAlreadyInUseException {
		return UseToken.INIT_TOKEN;
	}

	default void ignoreOwnership(Path ciphertextPath) {

	}

}
