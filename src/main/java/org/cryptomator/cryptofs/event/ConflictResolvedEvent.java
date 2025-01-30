package org.cryptomator.cryptofs.event;

import java.nio.file.Path;

public record ConflictResolvedEvent(Path cleartextPath, Path ciphertextPath, Path oldVersionCleartextPath, Path oldVersionCiphertextPath) implements FilesystemEvent{
}
