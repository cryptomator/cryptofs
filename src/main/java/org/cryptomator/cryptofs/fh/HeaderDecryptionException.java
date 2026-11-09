package org.cryptomator.cryptofs.fh;

import org.cryptomator.cryptofs.event.DecryptionFailedEvent;

import java.io.IOException;
import java.nio.file.Path;

/**
 * Thrown when a file header cannot be decrypted. Carries the {@link DecryptionFailedEvent}, which is delivered once the {@link OpenCryptoFiles#open(java.nio.file.Path, OpenCryptoFiles.OpenOperation) open operation} released its lock.
 */
class HeaderDecryptionException extends IOException {

	private final transient DecryptionFailedEvent event;

	HeaderDecryptionException(Path ciphertextPath, Exception cause) {
		super("Unable to decrypt header of file " + ciphertextPath, cause);
		this.event = new DecryptionFailedEvent(ciphertextPath, cause);
	}

	DecryptionFailedEvent getEvent() {
		return event;
	}
}
