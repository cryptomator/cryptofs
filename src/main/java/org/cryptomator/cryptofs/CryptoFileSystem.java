package org.cryptomator.cryptofs;

import java.io.IOException;
import java.nio.file.FileSystem;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * A {@link FileSystem} which allows access to encrypted data in a directory.
 * <p>
 * A CryptoFileSystem encrypts/decrypts data read/stored from/to it and uses a storage location for the encrypted data. The storage location is denoted by a {@link Path} and can thus be any location
 * itself accessible via a java.nio.FileSystem.
 * <p>
 * A CryptoFileSystem can be used as any other java.nio.FileSystem, e.g. by using the operations from {@link Files}.
 * 
 * @author Markus Kreusch
 * @see CryptoFileSystemProvider
 */
public abstract class CryptoFileSystem extends FileSystem {

	CryptoFileSystem() {
	}

	/**
	 * Provides the {@link Path} to the storage location of the vault - the location on the physical / delegate file system where encrypted data is stored.
	 * <p>
	 * This path has been passed in during creation and does not belong to this {@code CryptoFileSystem}. Thus this path can not be used in operations on this {@code CryptoFileSystem}.
	 * 
	 * @return the {@link Path} to the directory containing the encrypted files.
	 */
	public abstract Path getPathToVault();

	/**
	 * Provides the {@link Path} to the (data) ciphertext from a given cleartext path.
	 *
	 * @param cleartextPath absolute path to the cleartext file or folder belonging to this {@link CryptoFileSystem}. Internally the path must be an instance of {@link CryptoPath}
	 * @return the {@link Path} to ciphertext file or folder containing teh actual encrypted data
	 * @throws IOException
	 */
	public abstract Path getPathToDataCiphertext(Path cleartextPath) throws IOException;

	/**
	 * Provides file system performance statistics.
	 * 
	 * @return the {@link CryptoFileSystemStats} containing performance statistics for this {@code CryptoFileSystem}
	 */
	public abstract CryptoFileSystemStats getStats();

}
