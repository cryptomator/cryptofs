package org.cryptomator.cryptofs.event;

import java.nio.file.Path;
import java.time.Instant;

/**
 * Emitted, if a path within the cryptographic filesystem is accessed, but the directory representing it is missing identification files.
 *
 * @param timestamp timestamp of event appearance
 * @param cleartextPath path (string) within the cryptographic filesystem
 * @param ciphertextPath path of the incomplete, encrypted directory
 * @see org.cryptomator.cryptofs.health.type.UnknownType
 */
public record BrokenFileNodeEvent(Instant timestamp, String cleartextPath, Path ciphertextPath) implements FilesystemEvent {

	public BrokenFileNodeEvent(Path cleartextPath, Path ciphertextPath) {
		this(Instant.now(), cleartextPath.toString(), ciphertextPath);
	}

	@Override
	public Instant getTimestamp() {
		return timestamp;
	}
}
