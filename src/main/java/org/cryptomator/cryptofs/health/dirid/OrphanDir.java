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

	@Override
	public void fix(Path pathToVault, VaultConfig config, Masterkey masterkey, Cryptor cryptor) throws IOException {
		var sha1 = getSha1MessageDigest();
		String runId = Integer.toString((short) UUID.randomUUID().getMostSignificantBits(), 32);
		Path orphanedDir = pathToVault.resolve(Constants.DATA_DIR_NAME).resolve(this.dir);
		String orphanHash = dir.getParent().getFileName().toString() + dir.getFileName().toString();

		var stepParentDir = prepareCryptoFilesystem(pathToVault, cryptor.fileNameCryptor(), orphanHash);

		try (var orphanedContentStream = Files.newDirectoryStream(orphanedDir)) {
			AtomicInteger fileCounter = new AtomicInteger(1);
			AtomicInteger dirCounter = new AtomicInteger(1);
			AtomicInteger symlinkCounter = new AtomicInteger(1);
			String longNameSuffix = createClearnameToBeShortened(config.getShorteningThreshold());

			for (Path orphanedResource : orphanedContentStream) {
				var newClearName = switch (determineCiphertextFileType(orphanedResource)) {
					case FILE -> FILE_PREFIX + fileCounter.getAndIncrement();
					case DIRECTORY -> DIR_PREFIX + dirCounter.getAndIncrement();
					case SYMLINK -> SYMLINK_PREFIX + symlinkCounter.getAndIncrement();
				} + "_" + runId;
				adoptOrphanedResource(orphanedResource, newClearName, stepParentDir, cryptor.fileNameCryptor(), longNameSuffix, sha1);
			}
		}
		Files.delete(orphanedDir);
	}

	// visible for testing
	CryptoPathMapper.CiphertextDirectory prepareCryptoFilesystem(Path pathToVault, FileNameCryptor cryptor, String clearStepParentDirName) throws IOException {
		//determine path for cipher root
		Path dataDir = pathToVault.resolve(Constants.DATA_DIR_NAME);
		String rootDirHash = cryptor.hashDirectoryId(Constants.ROOT_DIR_ID);
		Path vaultCipherRootPath = dataDir.resolve(rootDirHash.substring(0, 2)).resolve(rootDirHash.substring(2)).toAbsolutePath();

		//check if recovery dir exists and has unique recovery id
		String cipherRecoveryDirName = convertClearToCiphertext(cryptor, Constants.RECOVERY_DIR_NAME, Constants.ROOT_DIR_ID);
		Path cipherRecoveryDirFile = vaultCipherRootPath.resolve(cipherRecoveryDirName + "/" + Constants.DIR_FILE_NAME);
		if (Files.notExists(cipherRecoveryDirFile, LinkOption.NOFOLLOW_LINKS)) {
			Files.createDirectory(cipherRecoveryDirFile.getParent());
			Files.writeString(cipherRecoveryDirFile, Constants.RECOVERY_DIR_ID, StandardCharsets.UTF_8, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE);
		} else {
			String uuid = Files.readString(cipherRecoveryDirFile, StandardCharsets.UTF_8);
			if (!Constants.RECOVERY_DIR_ID.equals(uuid)) {
				throw new FileAlreadyExistsException("Directory /" + Constants.RECOVERY_DIR_NAME + " already exists, but with wrong directory id.");
			}
		}
		String recoveryDirHash = cryptor.hashDirectoryId(Constants.RECOVERY_DIR_ID);
		Path cipherRecoveryDir = dataDir.resolve(recoveryDirHash.substring(0, 2)).resolve(recoveryDirHash.substring(2)).toAbsolutePath();
		Files.createDirectories(cipherRecoveryDir);

		//create "step-parent" directory to move orphaned files to
		String cipherStepParentDirName = convertClearToCiphertext(cryptor, clearStepParentDirName, Constants.RECOVERY_DIR_ID);
		Path cipherStepParentDirFile = cipherRecoveryDir.resolve(cipherStepParentDirName + "/" + Constants.DIR_FILE_NAME);
		final String stepParentUUID;
		if (Files.exists(cipherStepParentDirFile, LinkOption.NOFOLLOW_LINKS)) {
			stepParentUUID = Files.readString(cipherStepParentDirFile, StandardCharsets.UTF_8);
		} else {
			Files.createDirectory(cipherStepParentDirFile.getParent());
			stepParentUUID = UUID.randomUUID().toString();
			Files.writeString(cipherStepParentDirFile, stepParentUUID, StandardCharsets.UTF_8, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE);
		}
		String stepParentDirHash = cryptor.hashDirectoryId(stepParentUUID);
		Path stepParentDir = dataDir.resolve(stepParentDirHash.substring(0, 2)).resolve(stepParentDirHash.substring(2)).toAbsolutePath();
		Files.createDirectories(stepParentDir);
		return new CryptoPathMapper.CiphertextDirectory(stepParentUUID, stepParentDir);
	}

	// visible for testing
	void adoptOrphanedResource(Path oldCipherPath, String newClearname, CryptoPathMapper.CiphertextDirectory stepParentDir, FileNameCryptor cryptor, String longNameSuffix, MessageDigest sha1) throws IOException {
		if (oldCipherPath.toString().endsWith(Constants.DEFLATED_FILE_SUFFIX)) {
			var newCipherName = convertClearToCiphertext(cryptor, newClearname + longNameSuffix, stepParentDir.dirId);
			var deflatedName = BaseEncoding.base64Url().encode(sha1.digest(newCipherName.getBytes(StandardCharsets.UTF_8))) + Constants.DEFLATED_FILE_SUFFIX;
			Path targetPath = stepParentDir.path.resolve(deflatedName);
			Files.move(oldCipherPath, targetPath, StandardCopyOption.ATOMIC_MOVE);

			//adjust name.c9s
			try (var fc = Files.newByteChannel(targetPath.resolve(Constants.INFLATED_FILE_NAME), StandardOpenOption.WRITE, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING)) {
				fc.write(ByteBuffer.wrap(newCipherName.getBytes(StandardCharsets.UTF_8)));
			}
		} else {
			var newCipherName = convertClearToCiphertext(cryptor, newClearname, stepParentDir.dirId);
			Path targetPath = stepParentDir.path.resolve(newCipherName);
			Files.move(oldCipherPath, targetPath, StandardCopyOption.ATOMIC_MOVE);
		}
	}

	private static String createClearnameToBeShortened(int threshold) {
		int neededLength = (threshold - 4) / 4 * 3 - 16;
		return LONG_NAME_SUFFIX_BASE.repeat((neededLength % LONG_NAME_SUFFIX_BASE.length()) + 1);
	}

	private static String convertClearToCiphertext(FileNameCryptor cryptor, String clearTextName, String dirId) {
		return cryptor.encryptFilename(BaseEncoding.base64Url(), clearTextName, dirId.getBytes(StandardCharsets.UTF_8)) + Constants.CRYPTOMATOR_FILE_SUFFIX;
	}

	private static CiphertextFileType determineCiphertextFileType(Path ciphertextPath) {
		if (Files.exists(ciphertextPath.resolve(Constants.DIR_FILE_NAME), LinkOption.NOFOLLOW_LINKS)) {
			return CiphertextFileType.DIRECTORY;
		} else if (Files.exists(ciphertextPath.resolve(Constants.SYMLINK_FILE_NAME), LinkOption.NOFOLLOW_LINKS)) {
			return CiphertextFileType.SYMLINK;
		} else {
			return CiphertextFileType.FILE;
		}
	}

	private static MessageDigest getSha1MessageDigest() {
		try {
			return MessageDigest.getInstance("SHA1");
		} catch (NoSuchAlgorithmException e) {
			throw new IllegalStateException("Every JVM needs to provide a SHA1 implementation.");
		}
	}
}
