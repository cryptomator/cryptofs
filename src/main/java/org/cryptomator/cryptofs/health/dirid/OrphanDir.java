package org.cryptomator.cryptofs.health.dirid;

import com.google.common.io.BaseEncoding;
import org.cryptomator.cryptofs.CryptoFileSystemProperties;
import org.cryptomator.cryptofs.CryptoFileSystemProvider;
import org.cryptomator.cryptofs.CryptoPathMapper;
import org.cryptomator.cryptofs.VaultConfig;
import org.cryptomator.cryptofs.common.CiphertextFileType;
import org.cryptomator.cryptofs.common.Constants;
import org.cryptomator.cryptofs.health.api.DiagnosticResult;
import org.cryptomator.cryptolib.api.Cryptor;
import org.cryptomator.cryptolib.api.Masterkey;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import static org.cryptomator.cryptofs.health.api.CommonDetailKeys.ENCRYPTED_PATH;

/**
 * An orphan directory is a detached node, not referenced by any dir.c9r file.
 */
public class OrphanDir implements DiagnosticResult {

	private static final String LOST_AND_FOUND_DIR = "lost+found";

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
		//open cryptofilsystem and place lf dir
		Path orphanedDir = pathToVault.resolve(Constants.DATA_DIR_NAME).resolve(this.dir);
		String orphanHash = dir.getParent().getFileName().toString() + dir.getFileName().toString(); //TODO: is this the way? -> if the process is midterm aborted and later retried files already exist!
		try (var fs = CryptoFileSystemProvider.newFileSystem(pathToVault, CryptoFileSystemProperties.cryptoFileSystemProperties()
				.withKeyLoader(uri -> masterkey.clone())
				.withVaultConfigFilename("vault.cryptomator").build())) {
			Path lf = fs.getRootDirectories().iterator().next().resolve(LOST_AND_FOUND_DIR);
			Files.createDirectories(lf.resolve(orphanHash));
		}

		CryptoPathMapper.CiphertextDirectory cipherTargetDir = getCiphertextDirFileFromCleartext(cryptor, pathToVault, Path.of("/" + LOST_AND_FOUND_DIR + "/" + orphanHash));

		if (!Files.exists(cipherTargetDir.path)) {
			throw new IOException("Dir file of  not found " + cipherTargetDir.path);
		}

		try (var orphanedContentStream = Files.newDirectoryStream(orphanedDir)) {
			//	move resource to unfiddled dir in l+f and rename resource  (use dirId for associated data)
			AtomicInteger fileCounter = new AtomicInteger(1);
			AtomicInteger dirCounter = new AtomicInteger(1);
			AtomicInteger symlinkCounter = new AtomicInteger(1);
			String filePrefix = "file";
			String dirPrefix = "directory";
			String symlinkPrefix = "symlink";
			String veryLongSuffix = clearnameToBeDefinitelyShortend(cryptor, config.getShorteningThreshold());
			MessageDigest sha1Hasher = MessageDigest.getInstance("SHA-1");

			for (Path orphanedResource : orphanedContentStream) {
				if (orphanedResource.toString().endsWith(Constants.DEFLATED_FILE_SUFFIX)) {
					var newClearName = switch (determineCiphertextFileType(orphanedResource)) {
						case FILE -> filePrefix + fileCounter.getAndIncrement();
						case DIRECTORY -> dirPrefix + dirCounter.getAndIncrement();
						case SYMLINK -> symlinkPrefix + symlinkCounter.getAndIncrement();
					} + veryLongSuffix;
					var newCipherName = convertClearToCiphertext(cryptor, newClearName, cipherTargetDir.dirId) + Constants.CRYPTOMATOR_FILE_SUFFIX;
					//deflate
					var deflatedName = BaseEncoding.base64Url().encode(sha1Hasher.digest(newCipherName.getBytes(StandardCharsets.UTF_8))) + Constants.DEFLATED_FILE_SUFFIX;
					Path targetPath = cipherTargetDir.path.resolve(deflatedName);
					Files.move(orphanedResource, targetPath, StandardCopyOption.ATOMIC_MOVE);

					//adjust name.c9s
					try (var fc = Files.newByteChannel(targetPath.resolve(Constants.INFLATED_FILE_NAME), StandardOpenOption.WRITE, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING)) {
						fc.write(ByteBuffer.wrap(newCipherName.getBytes(StandardCharsets.UTF_8)));
					}
				} else {
					var newClearName = switch (determineCiphertextFileType(orphanedResource)) {
						case FILE -> filePrefix + fileCounter.getAndIncrement();
						case DIRECTORY -> dirPrefix + dirCounter.getAndIncrement();
						case SYMLINK -> symlinkPrefix + symlinkCounter.getAndIncrement();
					};
					var newCipherName = convertClearToCiphertext(cryptor, newClearName, cipherTargetDir.dirId) + Constants.CRYPTOMATOR_FILE_SUFFIX;
					Path targetPath = cipherTargetDir.path.resolve(newCipherName);
					Files.move(orphanedResource, targetPath, StandardCopyOption.ATOMIC_MOVE);
				}
			}
		} catch (NoSuchAlgorithmException e) {
			throw new NoClassDefFoundError("Every JVM must implement SHA-1 algorithm.");
		}
		Files.delete(orphanedDir);
	}

	private String clearnameToBeDefinitelyShortend(Cryptor cryptor, int threshold) {
		String base = "_withVeryLongName"; //all 1Byte chars in UTF8
		int neededLength = (int) Math.ceil(threshold*0.75 -16);
		if (neededLength > Integer.MAX_VALUE) {
			//TODO
			return "";
		} else {
			return base.repeat((neededLength % base.length()) + 1);
		}
	}

	private CryptoPathMapper.CiphertextDirectory getCiphertextDirFileFromCleartext(Cryptor cryptor, Path pathToVault, Path cleartext) throws IOException {
		String rootHash = cryptor.fileNameCryptor().hashDirectoryId(Constants.ROOT_DIR_ID);
		Path vaultCipherRootPath = pathToVault.resolve(Constants.DATA_DIR_NAME).resolve(rootHash.substring(0, 2)).resolve(rootHash.substring(2)).toAbsolutePath();

		String dirId = Constants.ROOT_DIR_ID;
		Path target = vaultCipherRootPath;

		for (Path component : cleartext) {
			String ciphertextName = convertClearToCiphertext(cryptor, component.getFileName().toString(), dirId) + Constants.CRYPTOMATOR_FILE_SUFFIX;
			Path dirFile = target.resolve(ciphertextName + "/" + Constants.DIR_FILE_NAME);
			dirId = new String(Files.readAllBytes(dirFile), StandardCharsets.UTF_8);
			String dirHash = cryptor.fileNameCryptor().hashDirectoryId(dirId);
			target = pathToVault.resolve(Constants.DATA_DIR_NAME).resolve(dirHash.substring(0, 2)).resolve(dirHash.substring(2)).toAbsolutePath();
		}

		return new CryptoPathMapper.CiphertextDirectory(dirId, target);
	}

	private String convertClearToCiphertext(Cryptor cryptor, String clearTextName, String dirId) {
		return cryptor.fileNameCryptor().encryptFilename(BaseEncoding.base64Url(), clearTextName, dirId.getBytes(StandardCharsets.UTF_8));
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
