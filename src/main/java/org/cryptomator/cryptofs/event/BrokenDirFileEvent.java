package org.cryptomator.cryptofs.event;

import java.nio.file.Path;
import java.time.Instant;

/**
 * Emitted, if a dir.c9r file is empty or exceeds 1000 Bytes.
 *
 * @param timestamp timestamp of event appearance
 * @param ciphertextPath path to the broken dir.c9r file
 */
public record BrokenDirFileEvent(Instant timestamp, Path ciphertextPath) implements FilesystemEvent {

	public BrokenDirFileEvent(Path ciphertextPath) {
		this(Instant.now(), ciphertextPath);
	}

	@Override
	public Instant getTimestamp() {
		return timestamp;
	}
}
