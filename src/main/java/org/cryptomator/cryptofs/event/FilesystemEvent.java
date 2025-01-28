package org.cryptomator.cryptofs.event;

public interface FilesystemEvent {

	static <T extends FilesystemEvent> LockedEvent toLockedEvent(T fse) {
		return toEvent(fse, LockedEvent.class);
	}

	static <T extends FilesystemEvent> DecryptionFailedEvent toDecryptionFailedEvent(T fse) throws ClassCastException {
		return toEvent(fse, DecryptionFailedEvent.class);
	}

	static <T extends FilesystemEvent> ConflictResolvedEvent toConflictResolvedEvent(T fse) throws ClassCastException {
		return toEvent(fse, ConflictResolvedEvent.class);
	}

	static <T extends FilesystemEvent, U extends FilesystemEvent> T toEvent(U o, Class<T> clazz) throws ClassCastException {
			return clazz.cast(o);
	}

	Type getType();

	enum Type {
		DECRYPTION_FAILED,
		CONFLICT_RESOLVED,
		LOCKED;
	}

}
