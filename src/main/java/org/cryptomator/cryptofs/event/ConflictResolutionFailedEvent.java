package org.cryptomator.cryptofs.event;

import java.nio.file.Path;

public record ConflictResolutionFailedEvent(Path cleartextPath, Path ciphertextPath , Exception reason) implements FilesystemEvent {
}
