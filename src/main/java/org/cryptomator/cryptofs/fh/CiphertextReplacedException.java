package org.cryptomator.cryptofs.fh;

import java.io.IOException;
import java.nio.file.Path;

/**
 * Thrown when the ciphertext file at the path of an open file is no longer that open file's, because it was replaced outside of this file system or unlinked by another open.
 * The open file has been detached by then, so {@link OpenCryptoFiles.OpenOperation} may retry with a fresh one, if {@link #retryable()}.
 */
class CiphertextReplacedException extends IOException {

	private final boolean retryable;

	CiphertextReplacedException(Path ciphertextPath, boolean retryable) {
		super("Ciphertext file is no longer the one of the open file: " + ciphertextPath);
		this.retryable = retryable;
	}

	boolean retryable() {
		return retryable;
	}
}
