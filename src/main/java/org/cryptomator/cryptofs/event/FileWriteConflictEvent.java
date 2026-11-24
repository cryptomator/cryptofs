package org.cryptomator.cryptofs.event;

import java.nio.file.Path;
import java.time.Instant;

/**
 * Emitted, if a write or save through an open file was refused, because its ciphertext changed outside of this file system while the file was open.
 * <p>
 * The version on disk stays intact, and the open file saves nothing more. Saves completed before the conflict may already be on disk.
 * The event fires at most once per open file. It arrives on its own thread, possibly after the failing call returned or after the file system closed.
 *
 * @param timestamp timestamp of event appearance
 * @param cleartextPath cleartext path of the file, or {@code null} if unknown
 * @param ciphertextPath path to the encrypted file, never {@code null}. For a shortened name, this is the inner {@code contents.c9r}
 */
public record FileWriteConflictEvent(Instant timestamp, String cleartextPath, Path ciphertextPath) implements FilesystemEvent {

	public FileWriteConflictEvent(String cleartextPath, Path ciphertextPath) {
		this(Instant.now(), cleartextPath, ciphertextPath);
	}

	@Override
	public Instant getTimestamp() {
		return timestamp;
	}
}
