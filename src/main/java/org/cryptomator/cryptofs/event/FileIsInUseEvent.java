package org.cryptomator.cryptofs.event;

import java.nio.file.Path;
import java.time.Instant;
import java.util.Properties;

public record FileIsInUseEvent(Instant timestamp, Path cleartext, Path ciphertext, Properties moreInfo) implements FilesystemEvent {

	public FileIsInUseEvent(Path cleartext, Path ciphertext, Properties moreInfo) {
		this(Instant.now(), cleartext, ciphertext, moreInfo);
	}

	@Override
	public Instant getTimestamp() {
		return timestamp;
	}
}
