package org.cryptomator.cryptofs.event;

import org.cryptomator.cryptolib.api.AuthenticationFailedException;

import java.nio.file.Path;

/**
 * Created, if decryption fails.
 * @param ciphertextPath
 * @param cleartextPath might be null
 * @param e
 */
public record DecryptionFailedEvent(Path ciphertextPath, Path cleartextPath, AuthenticationFailedException e) implements FilesystemEvent {

	@Override
	public Type getType() {
		return Type.DECRYPTION_FAILED;
	}
}
