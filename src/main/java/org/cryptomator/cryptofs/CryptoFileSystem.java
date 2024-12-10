package org.cryptomator.cryptofs;

import org.cryptomator.cryptofs.common.Constants;

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
	 * @throws java.nio.file.ProviderMismatchException if the cleartext path does not belong to this CryptoFileSystem
	 * @throws java.nio.file.NoSuchFileException if for the cleartext path no ciphertext resource exists
	 * @throws IOException if an I/O error occurs looking for the ciphertext resource
	 */
	public abstract Path getCiphertextPath(Path cleartextPath) throws IOException;

	/**
	 * Computes from a valid,encrypted node (file or folder) its cleartext name.
	 * <p>
	 * Due to the structure of a vault, an encrypted node is valid if:
	 * <ul>
	 *     <li>the path points into the vault (duh!)</li>
	 *     <li>the "file" extension is {@value Constants#CRYPTOMATOR_FILE_SUFFIX} or {@value Constants#DEFLATED_FILE_SUFFIX}</li>
	 *     <li>the node name is at least {@value Constants#MIN_CIPHER_NAME_LENGTH} characters long</li>
	 *     <li>it is located at depth 4 from the vault storage root, i.e. d/AB/CDEFG...XYZ/validFile.c9r</li>
	 * </ul>
	 *
	 * @param ciphertextNode path to the ciphertext file or directory
	 * @return the cleartext name of the ciphertext file or directory
	 * @throws java.nio.file.NoSuchFileException if the ciphertextFile does not exist
	 * @throws IOException if an I/O error occurs reading the ciphertext files
	 * @throws IllegalArgumentException if {@param ciphertextNode} is not a valid ciphertext content node of the vault
	 * @throws UnsupportedOperationException if the directory containing the {@param ciphertextNode} does not have a {@value Constants#DIR_ID_BACKUP_FILE_NAME} file
	 */
	public abstract String getCleartextName(Path ciphertextNode) throws IOException, UnsupportedOperationException;

	/**
	 * Provides file system performance statistics.
	 * 
	 * @return the {@link CryptoFileSystemStats} containing performance statistics for this {@code CryptoFileSystem}
	 */
	public abstract CryptoFileSystemStats getStats();

}
