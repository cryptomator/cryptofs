package org.cryptomator.cryptofs.event;

public abstract class FilesystemEvent {

	private final Type type;

	protected FilesystemEvent(Type type) {
		this.type = type;
	}

	LockedEvent toLockedEvent() {
		return toEvent(LockedEvent.class);
	}

	DecryptionFailedEvent toDecryptionFailedEvent() {
		return toEvent(DecryptionFailedEvent.class);
	}

	<T extends FilesystemEvent> T toEvent(Class<T> clazz) {
		try {
			return clazz.cast(this);
		} catch (ClassCastException e) {
			throw new IllegalCallerException();
		}
	}

	public Type getType() {
		return type;
	}

	public enum Type {
		DECRYPTION_FAILED,
		LOCKED;
	}

}
