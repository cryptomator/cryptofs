package org.cryptomator.cryptofs.health.dirid;

import com.google.common.io.BaseEncoding;
import org.cryptomator.cryptofs.CryptoPathMapper;
import org.cryptomator.cryptofs.VaultConfig;
import org.cryptomator.cryptofs.common.CiphertextFileType;
import org.cryptomator.cryptofs.common.Constants;
import org.cryptomator.cryptofs.health.api.DiagnosticResult;
import org.cryptomator.cryptolib.api.Cryptor;
import org.cryptomator.cryptolib.api.FileNameCryptor;
import org.cryptomator.cryptolib.api.Masterkey;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;

import static org.cryptomator.cryptofs.health.api.CommonDetailKeys.ENCRYPTED_PATH;

/**
 * An orphan directory is a detached node, not referenced by any dir.c9r file.
 */
public class OrphanDir implements DiagnosticResult {

	private static final String FILE_PREFIX = "file";
	private static final String DIR_PREFIX = "directory";
	private static final String SYMLINK_PREFIX = "symlink";
	private static final String LONG_NAME_SUFFIX_BASE = "_withVeryLongName";
	private static final MessageDigest SHA1_HASHER;

	static {
		try {
			SHA1_HASHER = MessageDigest.getInstance("SHA1");
		} catch (NoSuchAlgorithmException e) {
			throw new ExceptionInInitializerError("Every JVM needs to provide a SHA1 implementation.");
		}
	}

	final Path dir;

	OrphanDir(Path dir) {
		this.dir = dir;
	}

	@Override
	public Severity getSeverity() {
		return Severity.WARN;
	}

	@Override
	public String toString() {
		return String.format("Orphan directory: %s", dir);
	}

	@Override
	public Map<String, String> details() {
		return Map.of(ENCRYPTED_PATH, dir.toString());
	}

	// fix: create new dirId inside of L+F dir and rename existing dir accordingly.
	@Override
	public void fix(Path pathToVault, VaultConfig config, Masterkey masterkey, Cryptor cryptor) throws IOException {
		Path orphanedDir = pathToVault.resolve(Constants.DATA_DIR_NAME).resolve(this.dir);
		String orphanHash = dir.getParent().getFileName().toString() + dir.getFileName().toString(); //TODO: is this the way? -> if the process is midterm aborted and later retried files already exist!

		var stepParentDir = prepareCryptoFilesystem(pathToVault, cryptor.fileNameCryptor(), orphanHash);

		try (var orphanedContentStream = Files.newDirectoryStream(orphanedDir)) {
			//move resource to unfiddled dir in l+f and rename resource  (use dirId for associated data)
			AtomicInteger fileCounter = new AtomicInteger(1);
			AtomicInteger dirCounter = new AtomicInteger(1);
			AtomicInteger symlinkCounter = new AtomicInteger(1);
			String veryLongSuffix = createClearnameToBeShortened(config.getShorteningThreshold());

			for (Path orphanedResource : orphanedContentStream) {
				var newClearName = switch (determineCiphertextFileType(orphanedResource)) {
					case FILE -> FILE_PREFIX + fileCounter.getAndIncrement();
					case DIRECTORY -> DIR_PREFIX + dirCounter.getAndIncrement();
					case SYMLINK -> SYMLINK_PREFIX + symlinkCounter.getAndIncrement();
				};
				if (orphanedResource.toString().endsWith(Constants.DEFLATED_FILE_SUFFIX)) {
					var newCipherName = convertClearToCiphertext(cryptor.fileNameCryptor(), newClearName + veryLongSuffix, stepParentDir.dirId);
					var deflatedName = BaseEncoding.base64Url().encode(SHA1_HASHER.digest(newCipherName.getBytes(StandardCharsets.UTF_8))) + Constants.DEFLATED_FILE_SUFFIX;
					Path targetPath = stepParentDir.path.resolve(deflatedName);
					Files.move(orphanedResource, targetPath, StandardCopyOption.ATOMIC_MOVE);

					//adjust name.c9s
					try (var fc = Files.newByteChannel(targetPath.resolve(Constants.INFLATED_FILE_NAME), StandardOpenOption.WRITE, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING)) {
						fc.write(ByteBuffer.wrap(newCipherName.getBytes(StandardCharsets.UTF_8)));
					}
				} else {
					var newCipherName = convertClearToCiphertext(cryptor.fileNameCryptor(), newClearName, stepParentDir.dirId);
					Path targetPath = stepParentDir.path.resolve(newCipherName);
					Files.move(orphanedResource, targetPath, StandardCopyOption.ATOMIC_MOVE);
				}

			}
		}
		Files.delete(orphanedDir);
	}

	/* visisble for testing */
	CryptoPathMapper.CiphertextDirectory prepareCryptoFilesystem(Path pathToVault, FileNameCryptor cryptor, String clearStepParentDirName) throws IOException {
		Path dataDir = pathToVault.resolve(Constants.DATA_DIR_NAME);
		String rootDirHash = cryptor.hashDirectoryId(Constants.ROOT_DIR_ID);
		Path vaultCipherRootPath = dataDir.resolve(rootDirHash.substring(0, 2)).resolve(rootDirHash.substring(2)).toAbsolutePath();

		//create  if not existent with constant id
		String cipherRecoveryDirName = convertClearToCiphertext(cryptor, Constants.RECOVERY_DIR_NAME, Constants.ROOT_DIR_ID);
		Path cipherRecoveryDirFile = vaultCipherRootPath.resolve(cipherRecoveryDirName + "/" + Constants.DIR_FILE_NAME);
		if (Files.notExists(cipherRecoveryDirFile)) {
			Files.createDirectory(cipherRecoveryDirFile.getParent());
			Files.writeString(cipherRecoveryDirFile, Constants.RECOVERY_DIR_ID, StandardCharsets.UTF_8, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE);
		} else {
			String uuid = Files.readString(cipherRecoveryDirFile, StandardCharsets.UTF_8);
			if (!uuid.equals(Constants.RECOVERY_DIR_ID)) {
				throw new FileAlreadyExistsException("Directory /" + Constants.RECOVERY_DIR_NAME + " already exists, but with wrong directory id.");
			}
		}
		String recoveryDirHash = cryptor.hashDirectoryId(Constants.RECOVERY_DIR_ID);
		Path cipherRecoveryDir = dataDir.resolve(recoveryDirHash.substring(0, 2)).resolve(recoveryDirHash.substring(2)).toAbsolutePath();
		Files.createDirectories(cipherRecoveryDir);

		//create deorphanedDirectory
		String cipherStepParentDirName = convertClearToCiphertext(cryptor, clearStepParentDirName, Constants.RECOVERY_DIR_ID);
		Path cipherStepParentDirFile = cipherRecoveryDir.resolve(cipherStepParentDirName + "/" + Constants.DIR_FILE_NAME);
		Files.createDirectory(cipherStepParentDirFile.getParent());
		var stepParentUUID = UUID.randomUUID().toString();
		Files.writeString(cipherStepParentDirFile, stepParentUUID, StandardCharsets.UTF_8, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE);
		String stepParentDirHash = cryptor.hashDirectoryId(stepParentUUID);
		Path stepParentDir = dataDir.resolve(stepParentDirHash.substring(0, 2)).resolve(stepParentDirHash.substring(2)).toAbsolutePath();
		Files.createDirectories(stepParentDir);
		return new CryptoPathMapper.CiphertextDirectory(stepParentUUID, stepParentDir);
	}


	private String createClearnameToBeShortened(int threshold) {
		int neededLength = threshold / 4 * 3 - 16;
		return LONG_NAME_SUFFIX_BASE.repeat((neededLength % LONG_NAME_SUFFIX_BASE.length()) + 1);
	}

	private String convertClearToCiphertext(FileNameCryptor cryptor, String clearTextName, String dirId) {
		return cryptor.encryptFilename(BaseEncoding.base64Url(), clearTextName, dirId.getBytes(StandardCharsets.UTF_8)) + Constants.CRYPTOMATOR_FILE_SUFFIX;
	}

	private CiphertextFileType determineCiphertextFileType(Path ciphertextPath) {
		if (Files.exists(ciphertextPath.resolve(Constants.DIR_FILE_NAME), LinkOption.NOFOLLOW_LINKS)) {
			return CiphertextFileType.DIRECTORY;
		} else if (Files.exists(ciphertextPath.resolve(Constants.SYMLINK_FILE_NAME), LinkOption.NOFOLLOW_LINKS)) {
			return CiphertextFileType.SYMLINK;
		} else {
			return CiphertextFileType.FILE;
		}
	}
}
