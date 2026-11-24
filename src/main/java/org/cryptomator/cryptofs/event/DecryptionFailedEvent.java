package org.cryptomator.cryptofs.event;

import java.nio.file.Path;
import java.time.Instant;

/**
 * Emitted, if a decryption operation fails.
 * <p>
 * For a file header, the event is delivered on the opening thread once the open released its path lock, before the failing open returns. For a chunk, it arrives on its own thread, possibly after the failing call returned or after the file system closed.
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
