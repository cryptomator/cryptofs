package org.cryptomator.cryptofs.event;

import org.cryptomator.cryptolib.api.AuthenticationFailedException;

import java.nio.file.Path;
import java.util.concurrent.atomic.AtomicReference;

public class DecryptionFailedEvent extends FilesystemEvent {

	private final Path resource;
	private final AuthenticationFailedException e;

	public DecryptionFailedEvent(Path resource, AuthenticationFailedException e) {
		super(Type.DECRYPTION_FAILED);
		this.resource = resource;
		this.e = e;
	}

	public Path getResource() {
		return resource;
	}

}
