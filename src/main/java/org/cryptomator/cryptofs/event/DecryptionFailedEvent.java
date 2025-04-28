package org.cryptomator.cryptofs.event;

import java.nio.file.Path;
import java.time.Instant;

/**
 * Emitted, if a decryption operation fails.
 *
 * @param timestamp timestamp of event appearance
 * @param ciphertextPath path to the encrypted resource
 * @param e thrown exception
 */
public record DecryptionFailedEvent(Instant timestamp, Path ciphertextPath, Exception e) implements FilesystemEvent {

	public DecryptionFailedEvent(Path ciphertextPath, Exception e) {
		this(Instant.now(), ciphertextPath, e);
	}

	@Override
	public Instant getTimestamp() {
		return timestamp;
	}
}
