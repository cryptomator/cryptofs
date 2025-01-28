package org.cryptomator.cryptofs.event;

public record LockedEvent() implements FilesystemEvent {

	@Override
	public Type getType() {
		return Type.LOCKED;
	}
}
