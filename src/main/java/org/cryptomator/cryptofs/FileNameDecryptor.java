package org.cryptomator.cryptofs;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.io.BaseEncoding;
import org.cryptomator.cryptofs.common.Constants;
import org.cryptomator.cryptofs.common.StringUtils;
import org.cryptomator.cryptolib.api.CryptoException;
import org.cryptomator.cryptolib.api.Cryptor;
import org.cryptomator.cryptolib.api.FileNameCryptor;

import jakarta.inject.Inject;
import java.io.IOException;
import java.nio.file.FileSystemException;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.util.stream.Stream;

/**
 * @see CryptoFileSystem#getCleartextName(Path)
 */
@CryptoFileSystemScoped
class FileNameDecryptor {

	private final DirectoryIdBackup dirIdBackup;
	private final LongFileNameProvider longFileNameProvider;
	private final Path vaultPath;
	private final FileNameCryptor fileNameCryptor;

	@Inject
	public FileNameDecryptor(@PathToVault Path vaultPath, Cryptor cryptor, DirectoryIdBackup dirIdBackup, LongFileNameProvider longFileNameProvider) {
		this.vaultPath = vaultPath;
		this.fileNameCryptor = cryptor.fileNameCryptor();
		this.dirIdBackup = dirIdBackup;
		this.longFileNameProvider = longFileNameProvider;
	}

	public String decryptFilename(Path ciphertextNode) throws IOException, UnsupportedOperationException {
		validatePath(ciphertextNode.toAbsolutePath());
		return decryptFilenameInternal(ciphertextNode);
	}

	@VisibleForTesting
	String decryptFilenameInternal(Path ciphertextNode) throws IOException, UnsupportedOperationException {
		byte[] dirId = null;
		try {
			dirId = dirIdBackup.read(ciphertextNode.getParent());
		} catch (NoSuchFileException e) {
			throw new UnsupportedOperationException("Directory does not have a " + Constants.DIR_ID_BACKUP_FILE_NAME + " file.");
		} catch (CryptoException | IllegalStateException e) {
			throw new FileSystemException(ciphertextNode.toString(), null, "Decryption of dirId backup file failed:" + e);
		}
		var fullCipherNodeName = ciphertextNode.getFileName().toString();
		var cipherNodeExtension = fullCipherNodeName.substring(fullCipherNodeName.length() - 4);

		String actualEncryptedName = switch (cipherNodeExtension) {
			case Constants.CRYPTOMATOR_FILE_SUFFIX -> StringUtils.removeEnd(fullCipherNodeName, Constants.CRYPTOMATOR_FILE_SUFFIX);
			case Constants.DEFLATED_FILE_SUFFIX -> longFileNameProvider.inflate(ciphertextNode);
			default -> throw new IllegalStateException("SHOULD NOT REACH HERE");
		};
		try {
			return fileNameCryptor.decryptFilename(BaseEncoding.base64Url(), actualEncryptedName, dirId);
		} catch (CryptoException e) {
			throw new FileSystemException(ciphertextNode.toString(), null, "Filname decryption failed:" + e);
		}
	}

	@VisibleForTesting
	void validatePath(Path absolutePath) {
		if (!belongsToVault(absolutePath)) {
			throw new IllegalArgumentException("Node %s is not a part of vault %s".formatted(absolutePath, vaultPath));
		}
		if (!isAtCipherNodeLevel(absolutePath)) {
			throw new IllegalArgumentException("Node %s is not located at depth 4 from vault storage root".formatted(absolutePath));
		}
		if (!(hasCipherNodeExtension(absolutePath) && hasMinimumFileNameLength(absolutePath))) {
			throw new IllegalArgumentException("Node %s does not end with %s or %s or filename is shorter than %d characters.".formatted(absolutePath, Constants.CRYPTOMATOR_FILE_SUFFIX, Constants.DEFLATED_FILE_SUFFIX, Constants.MIN_CIPHER_NAME_LENGTH));
		}
	}

	boolean hasCipherNodeExtension(Path p) {
		var name = p.getFileName();
		return name != null && Stream.of(Constants.CRYPTOMATOR_FILE_SUFFIX, Constants.DEFLATED_FILE_SUFFIX).anyMatch(name.toString()::endsWith);
	}

	boolean isAtCipherNodeLevel(Path absolutPah) {
		if (!absolutPah.isAbsolute()) {
			throw new IllegalArgumentException("Path " + absolutPah + "must be absolute");
		}
		return absolutPah.subpath(vaultPath.getNameCount(), absolutPah.getNameCount()).getNameCount() == 4;
	}

	boolean hasMinimumFileNameLength(Path p) {
		return p.getFileName().toString().length() >= Constants.MIN_CIPHER_NAME_LENGTH;
	}

	boolean belongsToVault(Path p) {
		return p.startsWith(vaultPath);
	}
}
