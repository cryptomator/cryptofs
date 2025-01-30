package org.cryptomator.cryptofs.event;

import org.cryptomator.cryptolib.api.AuthenticationFailedException;

import java.nio.file.Path;

/**
 * Emitted, if a decryption operation fails.
 *
 * @param cleartextPath path within the cryptographic filesystem
 * @param ciphertextPath path to the encrypted resource
 * @param e thrown exception
 */
public record DecryptionFailedEvent(Path cleartextPath, Path ciphertextPath, AuthenticationFailedException e) implements FilesystemEvent {

}
