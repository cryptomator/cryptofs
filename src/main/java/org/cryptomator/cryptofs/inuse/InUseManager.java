package org.cryptomator.cryptofs.inuse;

import java.nio.file.Path;
import java.util.Optional;

/**
 * The InUseManager offers methods to
 * <ul>
 * 	<li>determine if a file is in-use by a different filesystem</li>
 * 	<li>create an in-use-file and claim ownership of it</li>
 * 	<li>ignore the in-use-file for a ciphertext path</li>
 * </ul>
 */
public interface InUseManager {

	/**
	 * Checks if the given ciphertext path is used by others.
	 *
	 * @param ciphertextPath Path to the ciphertext file for which the usage is checked
	 * @return {@code true} if the file is <it>used</it> by others. {@code false} otherwise
	 */
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


	/**
	 * Marks the given ciphertextpath as <em>used</em>.
	 *
	 * @param ciphertextPath Path to the ciphertext file which should be marked as used.
	 * @return A {@link UseToken} representing a use-ship for this file
	 * @throws FileAlreadyInUseException if the file is already in use by a different owner
	 */
	default UseToken use(Path ciphertextPath) throws FileAlreadyInUseException {
		return UseToken.INIT_TOKEN;
	}

	default void ignoreInUse(Path ciphertextPath) {

	}

}
