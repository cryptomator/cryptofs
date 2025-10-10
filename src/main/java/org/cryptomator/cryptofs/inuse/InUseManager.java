package org.cryptomator.cryptofs.inuse;

import java.nio.file.Path;
import java.time.Instant;
import java.util.Optional;

public interface InUseManager {

	default boolean isInUseByOthers(Path ciphertextPath) {
		return false;
	}

	/**
	 * Get information about the usage info of a file.
	 *
	 * @param ciphertextPath Path to the ciphertext file for which the {@link UseInfo} is collected
	 * @return Optional containing {@link UseInfo}. If there is no usage information, an empty Optional is returned.
	 */
	default Optional<UseInfo> getUseInfo(Path ciphertextPath) {
		return Optional.empty();
	}


	default UseToken use(Path ciphertextPath) throws FileAlreadyInUseException {
		return UseToken.INIT_TOKEN;
	}

	default void ignoreInUse(Path ciphertextPath) {

	}

	record UseInfo(String owner, Instant lastUpdated) {

	}

}
