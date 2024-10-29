package org.cryptomator.cryptofs;

import java.nio.file.Path;
import java.util.Objects;

//own file due to dagger

/**
 * Represents a ciphertext directory without it's mount point in the virtual filesystem.
 *
 * @param dirId The (ciphertext) dir id (not encrypted, just a uuid)
 * @param path The path to content directory (which contains the actual encrypted files and links to subdirectories)
 */
public record CiphertextDirectory(String dirId, Path path) {

	public CiphertextDirectory(String dirId, Path path) {
		this.dirId = Objects.requireNonNull(dirId);
		this.path = Objects.requireNonNull(path);
	}

}
