package org.cryptomator.cryptofs.event;

import org.cryptomator.cryptofs.inuse.UseInfo;

import java.nio.file.Path;
import java.time.Instant;
import java.util.Properties;

public record FileIsInUseEvent(Instant timestamp, Path cleartext, Path ciphertext, String owner, Instant lastUpdated) implements FilesystemEvent {

	public FileIsInUseEvent(Path cleartext, Path ciphertext, String owner, Instant lastUpdated) {
		this(Instant.now(), cleartext, ciphertext, owner, lastUpdated);
	}

	@Override
	public Instant getTimestamp() {
		return timestamp;
	}
}
