package org.cryptomator.cryptofs.event;

import java.nio.file.Path;

/**
 * Emitted, if a conflict inside an encrypted directory was resolved.
 * <p>
 * A conflict exists, if two encrypted files with the same base64url string exist, but the second file has an arbitrary suffix before the file extension.
 * The file <i>without</i> the suffix is called <b>canonical</b>.
 * The file <i>with the suffix</i> is called <b>conflicting</b>
 * On successful conflict resolution the conflicting file is renamed to the <b>resolved</b> file
 *
 * @param canonicalCleartextPath path of the canonical file within the cryptographic filesystem
 * @param conflictingCiphertextPath path of the encrypted, conflicting file
 * @param resolvedCleartextPath path of the resolved file within the cryptographic filesystem
 * @param resolvedCiphertextPath path of the resolved, encrypted file
 */
public record ConflictResolvedEvent(Path canonicalCleartextPath, Path conflictingCiphertextPath, Path resolvedCleartextPath, Path resolvedCiphertextPath) implements FilesystemEvent {

}
