package org.cryptomator.cryptofs.event;

import java.nio.file.Path;

/**
 * Emitted, if a conflict inside an encrypted directory was resolved
 *
 * @param cleartextPath path within the cryptographic filesystem
 * @param ciphertextPath path to the encrypted resource
 * @param oldVersionCleartextPath path within the cryptographic filesystem of the renamed resource
 * @param oldVersionCiphertextPath path to the renamed, encrypted resource
 */
public record ConflictResolvedEvent(Path cleartextPath, Path ciphertextPath, Path oldVersionCleartextPath, Path oldVersionCiphertextPath) implements FilesystemEvent {

}
