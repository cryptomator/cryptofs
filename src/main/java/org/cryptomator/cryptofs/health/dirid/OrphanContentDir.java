package org.cryptomator.cryptofs.health.dirid;

import com.google.common.io.BaseEncoding;
import org.cryptomator.cryptofs.CiphertextDirectory;
import org.cryptomator.cryptofs.DirectoryIdBackup;
import org.cryptomator.cryptofs.VaultConfig;
import org.cryptomator.cryptofs.common.CiphertextFileType;
import org.cryptomator.cryptofs.common.Constants;
import org.cryptomator.cryptofs.health.api.DiagnosticResult;
import org.cryptomator.cryptolib.api.AuthenticationFailedException;
import org.cryptomator.cryptolib.api.Cryptor;
import org.cryptomator.cryptolib.api.FileNameCryptor;
import org.cryptomator.cryptolib.api.Masterkey;
import org.cryptomator.cryptolib.common.ByteBuffers;
import org.cryptomator.cryptolib.common.DecryptingReadableByteChannel;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.ByteChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;

import static org.cryptomator.cryptofs.health.api.CommonDetailKeys.ENCRYPTED_PATH;

/**
 * An orphan directory is a detached node, not referenced by any dir.c9r file.
 */
public class OrphanContentDir implements DiagnosticResult {

	private static final Logger LOG = LoggerFactory.getLogger(OrphanContentDir.class);

	private static final String FILE_PREFIX = "file";
	private static final String DIR_PREFIX = "directory";
	private static final String SYMLINK_PREFIX = "symlink";
	private static final String LONG_NAME_SUFFIX_BASE = "_withVeryLongName";

	final Path contentDir;

	OrphanContentDir(Path contentDir) {
		this.contentDir = contentDir;
	}

	@Override
	public Severity getSeverity() {
		return Severity.WARN;
	}

	@Override
	public String toString() {
		return String.format("Orphan directory: %s", contentDir);
	}

	@Override
	public Map<String, String> details() {
		return Map.of(ENCRYPTED_PATH, contentDir.toString());
	}

	@Override
	public Optional<Fix> getFix(Path pathToVault, VaultConfig config, Masterkey masterkey, Cryptor cryptor) {
		return Optional.of(() -> fix(pathToVault, config, cryptor));
	}

	private void fix(Path pathToVault, VaultConfig config, Cryptor cryptor) throws IOException {
		var sha1 = getSha1MessageDigest();
		String runId = Integer.toString((short) UUID.randomUUID().getMostSignificantBits(), 32);
		Path dataDir = pathToVault.resolve(Constants.DATA_DIR_NAME);
		Path orphanedDir = dataDir.resolve(this.contentDir);
		String orphanDirIdHash = contentDir.getParent().getFileName().toString() + contentDir.getFileName().toString();

		Path recoveryDir = prepareRecoveryDir(pathToVault, cryptor.fileNameCryptor());
		if (recoveryDir.toAbsolutePath().equals(orphanedDir.toAbsolutePath())) {
			return; //recovery dir was orphaned, already recovered by prepare method
		}

		var stepParentDir = prepareStepParent(dataDir, recoveryDir, cryptor, orphanDirIdHash);
		AtomicInteger fileCounter = new AtomicInteger(1);
		AtomicInteger dirCounter = new AtomicInteger(1);
		AtomicInteger symlinkCounter = new AtomicInteger(1);
		String longNameSuffix = createClearnameToBeShortened(config.getShorteningThreshold());
		Optional<String> dirId = retrieveDirId(orphanedDir, cryptor);

		try (var orphanedContentStream = Files.newDirectoryStream(orphanedDir, this::matchesEncryptedContentPattern)) {
			for (Path orphanedResource : orphanedContentStream) {
				boolean isShortened = orphanedResource.toString().endsWith(Constants.DEFLATED_FILE_SUFFIX);
				//@formatter:off
				var newClearName = dirId.map(id -> {
							try {
								return decryptFileName(orphanedResource, isShortened, id, cryptor.fileNameCryptor());
							} catch (IOException | AuthenticationFailedException e) {
								LOG.warn("Unable to read and decrypt file name of {}:", orphanedResource, e);
								return null;
							}})
						.orElseGet(() ->
							switch (determineCiphertextFileType(orphanedResource)) {
								case FILE -> FILE_PREFIX + fileCounter.getAndIncrement();
								case DIRECTORY -> DIR_PREFIX + dirCounter.getAndIncrement();
								case SYMLINK -> SYMLINK_PREFIX + symlinkCounter.getAndIncrement();
							} + "_" + runId + (isShortened ? longNameSuffix : ""));
				//@formatter:on
				adoptOrphanedResource(orphanedResource, newClearName, isShortened, stepParentDir, cryptor.fileNameCryptor(), sha1);
			}
		}
		Files.deleteIfExists(orphanedDir.resolve(Constants.DIR_BACKUP_FILE_NAME));
		try (var nonCryptomatorFiles = Files.newDirectoryStream(orphanedDir)) {
			for (Path p : nonCryptomatorFiles) {
				Files.move(p, stepParentDir.path().resolve(p.getFileName()), LinkOption.NOFOLLOW_LINKS);
			}
		}
		Files.delete(orphanedDir);
	}

	//see also DirectoryStreamFactory
	private boolean matchesEncryptedContentPattern(Path path) {
		var tmp = path.getFileName().toString();
		return tmp.length() >= Constants.MIN_CIPHER_NAME_LENGTH //
				&& (tmp.endsWith(Constants.CRYPTOMATOR_FILE_SUFFIX) || tmp.endsWith(Constants.DEFLATED_FILE_SUFFIX));
	}

	//visible for testing
	Path prepareRecoveryDir(Path pathToVault, FileNameCryptor cryptor) throws IOException {
		Path dataDir = pathToVault.resolve(Constants.DATA_DIR_NAME);
		String rootDirHash = cryptor.hashDirectoryId(Constants.ROOT_DIR_ID);
		Path vaultCipherRootPath = dataDir.resolve(rootDirHash.substring(0, 2)).resolve(rootDirHash.substring(2)).toAbsolutePath();

		//check if recovery dir exists and has unique recovery id
		String cipherRecoveryDirName = encrypt(cryptor, Constants.RECOVERY_DIR_NAME, Constants.ROOT_DIR_ID);
		Path cipherRecoveryDirFile = vaultCipherRootPath.resolve(cipherRecoveryDirName + "/" + Constants.DIR_FILE_NAME);
		if (Files.notExists(cipherRecoveryDirFile, LinkOption.NOFOLLOW_LINKS)) {
			Files.createDirectories(cipherRecoveryDirFile.getParent());
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

		return cipherRecoveryDir;
	}

	// visible for testing
	CiphertextDirectory prepareStepParent(Path dataDir, Path cipherRecoveryDir, Cryptor cryptor, String clearStepParentDirName) throws IOException {
		//create "stepparent" directory to move orphaned files to
		String cipherStepParentDirName = encrypt(cryptor.fileNameCryptor(), clearStepParentDirName, Constants.RECOVERY_DIR_ID);
		Path cipherStepParentDirFile = cipherRecoveryDir.resolve(cipherStepParentDirName + "/" + Constants.DIR_FILE_NAME);
		final String stepParentUUID;
		if (Files.exists(cipherStepParentDirFile, LinkOption.NOFOLLOW_LINKS)) {
			stepParentUUID = Files.readString(cipherStepParentDirFile, StandardCharsets.UTF_8);
		} else {
			Files.createDirectories(cipherStepParentDirFile.getParent());
			stepParentUUID = UUID.randomUUID().toString();
			Files.writeString(cipherStepParentDirFile, stepParentUUID, StandardCharsets.UTF_8, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE);
		}
		String stepParentDirHash = cryptor.fileNameCryptor().hashDirectoryId(stepParentUUID);
		Path stepParentDir = dataDir.resolve(stepParentDirHash.substring(0, 2)).resolve(stepParentDirHash.substring(2)).toAbsolutePath();
		Files.createDirectories(stepParentDir);
		var stepParentCipherDir = new CiphertextDirectory(stepParentUUID, stepParentDir);
		//only if it does not exist
		try {
			DirectoryIdBackup.backupManually(cryptor, stepParentCipherDir);
		} catch (FileAlreadyExistsException e) {
			// already exists due to a previous recovery attempt
		}
		return stepParentCipherDir;
	}

	//visible for testing
	Optional<String> retrieveDirId(Path orphanedDir, Cryptor cryptor) {
		var dirIdFile = orphanedDir.resolve(Constants.DIR_BACKUP_FILE_NAME);
		var dirIdBuffer = ByteBuffer.allocate(36); //a dir id contains at most 36 ascii chars

		try (var channel = Files.newByteChannel(dirIdFile, StandardOpenOption.READ); //
			 var decryptingChannel = createDecryptingReadableByteChannel(channel, cryptor)) {
			ByteBuffers.fill(decryptingChannel, dirIdBuffer);
			dirIdBuffer.flip();
		} catch (IOException e) {
			LOG.info("Unable to read {}.", dirIdFile, e);
			return Optional.empty();
		}

		return Optional.of(StandardCharsets.US_ASCII.decode(dirIdBuffer).toString());
	}

	//exists and visible for testability
	DecryptingReadableByteChannel createDecryptingReadableByteChannel(ByteChannel channel, Cryptor cryptor) {
		return new DecryptingReadableByteChannel(channel, cryptor, true);
	}

	//visible for testing
	String decryptFileName(Path orphanedResource, boolean isShortened, String dirId, FileNameCryptor cryptor) throws IOException, AuthenticationFailedException {
		final String filenameWithExtension;
		if (isShortened) {
			filenameWithExtension = Files.readString(orphanedResource.resolve(Constants.INFLATED_FILE_NAME));
		} else {
			filenameWithExtension = orphanedResource.getFileName().toString();
		}

		final String filename = filenameWithExtension.substring(0, filenameWithExtension.length() - Constants.CRYPTOMATOR_FILE_SUFFIX.length());
		return cryptor.decryptFilename(BaseEncoding.base64Url(), filename, dirId.getBytes(StandardCharsets.UTF_8));
	}

	// visible for testing
	void adoptOrphanedResource(Path oldCipherPath, String newClearName, boolean isShortened, CiphertextDirectory stepParentDir, FileNameCryptor cryptor, MessageDigest sha1) throws IOException {
		var newCipherName = encrypt(cryptor, newClearName, stepParentDir.dirId());
		if (isShortened) {
			var deflatedName = BaseEncoding.base64Url().encode(sha1.digest(newCipherName.getBytes(StandardCharsets.UTF_8))) + Constants.DEFLATED_FILE_SUFFIX;
			Path targetPath = stepParentDir.path().resolve(deflatedName);
			Files.move(oldCipherPath, targetPath);

			//adjust name.c9s
			try (var fc = Files.newByteChannel(targetPath.resolve(Constants.INFLATED_FILE_NAME), StandardOpenOption.WRITE, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING)) {
				fc.write(ByteBuffer.wrap(newCipherName.getBytes(StandardCharsets.UTF_8)));
			}
		} else {
			Path targetPath = stepParentDir.path().resolve(newCipherName);
			Files.move(oldCipherPath, targetPath);
		}
	}

	private static String createClearnameToBeShortened(int threshold) {
		int neededLength = (threshold - 4) / 4 * 3 - 16;
		return LONG_NAME_SUFFIX_BASE.repeat((neededLength % LONG_NAME_SUFFIX_BASE.length()) + 1);
	}

	private static String encrypt(FileNameCryptor cryptor, String clearTextName, String dirId) {
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
