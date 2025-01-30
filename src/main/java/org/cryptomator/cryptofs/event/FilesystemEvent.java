package org.cryptomator.cryptofs.event;

public sealed interface FilesystemEvent permits ConflictResolutionFailedEvent, ConflictResolvedEvent, DecryptionFailedEvent {

}
