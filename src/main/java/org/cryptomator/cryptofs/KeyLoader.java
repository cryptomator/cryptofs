package org.cryptomator.cryptofs;

@FunctionalInterface
public interface KeyLoader {

	/**
	 * Loads a key required to unlock a vault.
	 * <p>
	 * This might be a long-running operation, as it may require user input or expensive computations.
	 *
	 * @param keyId a string uniquely identifying the source of the key and its identity, if multiple keys can be obtained from the same source
	 * @return The raw key bytes. Must not be null
	 * @throws KeyLoadingFailedException Thrown when it is impossible to fulfill the request
	 */
	byte[] loadKey(String keyId) throws KeyLoadingFailedException;

}
