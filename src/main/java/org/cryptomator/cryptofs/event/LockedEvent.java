package org.cryptomator.cryptofs.event;

public class LockedEvent extends FilesystemEvent {

	public LockedEvent() {
		super(Type.LOCKED);
	}

}
