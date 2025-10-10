package org.cryptomator.cryptofs.event;

import java.nio.file.Path;
import java.time.Instant;

public record FileIsInUseEvent(Instant timestamp, Path cleartext, Path ciphertext, String owner, Instant lastUpdated, Runnable ignoreMethod) implements FilesystemEvent {

	public FileIsInUseEvent(Path cleartext, Path ciphertext, String owner, Instant lastUpdated, Runnable ignoreMethod) {
		this(Instant.now(), cleartext, ciphertext, owner, lastUpdated, ignoreMethod);
	}

	@Override
	public Instant getTimestamp() {
		return timestamp;
	}

	public void ignoreInUse() {
		ignoreMethod.run();
	}

}
