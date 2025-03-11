package org.cryptomator.cryptofs.event;

import java.nio.file.Path;

/**
 * Emitted, if a dir.c9r file is empty or exceeds 1000 Bytes.
 *
 * @param ciphertextPath path to the broken dir.c9r file
 */
public record BrokenDirFileEvent(Path ciphertextPath) implements FilesystemEvent {

}
