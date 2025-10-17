package org.cryptomator.cryptofs.event;

import java.nio.file.Path;
import java.time.Instant;

/**
 * @param timestamp timestamp of event appearance
 * @param cleartextPath path (string) within the cryptographic filesystem
 * @param ciphertextPath path to the encrypted file
 * @param owner Name of the owner of the in-use-file
 * @param lastUpdated Time of last in-use-file update
 * @param ignoreMethod Method to ignore the use-status of the encrypted file for a short duration
 */
public record FileIsInUseEvent(Instant timestamp, String cleartextPath, Path ciphertextPath, String owner, Instant lastUpdated, Runnable ignoreMethod) implements FilesystemEvent {

	public FileIsInUseEvent(Path cleartextPath, Path ciphertextPath, String owner, Instant lastUpdated, Runnable ignoreMethod) {
		this(Instant.now(), cleartextPath.toString(), ciphertextPath, owner, lastUpdated, ignoreMethod);
	}

	@Override
	public Instant getTimestamp() {
		return timestamp;
	}

}
