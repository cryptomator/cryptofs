package org.cryptomator.cryptofs.event;

import java.nio.file.Path;

/**
 * Emitted, if the conflict resolution inside an encrypted directory failed
 *
 * @param cleartextPath path within the cryptographic filesystem
 * @param ciphertextPath path to the encrypted resource with the broken filename
 * @param reason exception, why the resolution failed
 */
public record ConflictResolutionFailedEvent(Path cleartextPath, Path ciphertextPath, Exception reason) implements FilesystemEvent {

}
