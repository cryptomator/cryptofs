package org.cryptomator.cryptofs.event;

import java.nio.file.Path;
import java.time.Instant;

/**
 * Emitted, if the conflict resolution inside an encrypted directory failed
 *
 * @param timestamp timestamp of event appearance
 * @param canonicalCleartextPath path of the canonical file within the cryptographic filesystem
 * @param conflictingCiphertextPath path of the encrypted, conflicting file
 * @param reason exception, why the resolution failed
 */
public record ConflictResolutionFailedEvent(Instant timestamp, Path canonicalCleartextPath, Path conflictingCiphertextPath, Exception reason) implements FilesystemEvent {

	public ConflictResolutionFailedEvent(Path canonicalCleartextPath, Path conflictingCiphertextPath, Exception reason) {
		this(Instant.now(), canonicalCleartextPath, conflictingCiphertextPath, reason);
	}

	@Override
	public Instant getTimestamp() {
		return timestamp;
	}
}
