package org.cryptomator.cryptofs.event;

import org.cryptomator.cryptolib.api.AuthenticationFailedException;

import java.nio.file.Path;

/**
 * Emitted, if a decryption operation fails.
 *
 * @param ciphertextPath path to the encrypted resource
 * @param e thrown exception
 */
public record DecryptionFailedEvent(Path ciphertextPath, Exception e) implements FilesystemEvent {

}
