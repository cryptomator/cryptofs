package org.cryptomator.cryptofs.fh;

import java.io.IOException;
import java.nio.file.Path;

/**
 * Thrown when an open file was closed after {@link OpenCryptoFiles.OpenOperation} got it, because its last channel or the file system closed in between.
 * A closed open file is no longer registered, and its cached header and size may no longer match the ciphertext, so {@link OpenCryptoFiles.OpenOperation} retries with a fresh one.
 */
class OpenFileRetiredException extends IOException {

	OpenFileRetiredException(Path ciphertextPath) {
		super("Open file was closed while opening: " + ciphertextPath);
	}
}
