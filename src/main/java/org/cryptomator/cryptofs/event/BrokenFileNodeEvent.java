package org.cryptomator.cryptofs.event;

import java.nio.file.Path;

/**
 * Emitted, if a path within the cryptographic filesystem is accessed, but the directory representing it is missing identification files.
 *
 * @param cleartextPath path within the cryptographic filesystem
 * @param ciphertextPath path of the incomplete, encrypted directory
 *
 * @see org.cryptomator.cryptofs.health.type.UnknownType
 */
public record BrokenFileNodeEvent(Path cleartextPath, Path ciphertextPath) implements FilesystemEvent {

}
