package org.cryptomator.cryptofs.event;

import java.nio.file.Path;

/**
 * Emitted, if the conflict resolution inside an encrypted directory failed
 *
 * @param canonicalCleartextPath path of the canonical file within the cryptographic filesystem
 * @param conflictingCiphertextPath path of the encrypted, conflicting file
 * @param reason exception, why the resolution failed
 */
public record ConflictResolutionFailedEvent(Path canonicalCleartextPath, Path conflictingCiphertextPath, Exception reason) implements FilesystemEvent {

}
