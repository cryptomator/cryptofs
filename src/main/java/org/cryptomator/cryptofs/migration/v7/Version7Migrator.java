/*******************************************************************************
 * Copyright (c) 2017 Skymatic UG (haftungsbeschränkt).
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE file.
 *******************************************************************************/
package org.cryptomator.cryptofs.migration.v7;

import com.google.common.io.BaseEncoding;
import org.cryptomator.cryptofs.BackupUtil;
import org.cryptomator.cryptofs.Constants;
import org.cryptomator.cryptofs.migration.api.Migrator;
import org.cryptomator.cryptolib.api.Cryptor;
import org.cryptomator.cryptolib.api.CryptorProvider;
import org.cryptomator.cryptolib.api.InvalidPassphraseException;
import org.cryptomator.cryptolib.api.KeyFile;
import org.cryptomator.cryptolib.api.UnsupportedVaultFormatException;
import org.cryptomator.cryptolib.common.MessageDigestSupplier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Inject;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.SeekableByteChannel;
import java.nio.file.FileVisitOption;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.Map;

import static java.nio.charset.StandardCharsets.UTF_8;

public class Version7Migrator implements Migrator {

	private static final Logger LOG = LoggerFactory.getLogger(Version7Migrator.class);

	private static final BaseEncoding BASE32 = BaseEncoding.base32();
	private static final int FILENAME_BUFFER_SIZE = 10 * 1024;
	private static final String NEW_SHORTENED_SUFFIX = ".c9s";
	private static final String NEW_NORMAL_SUFFIX = ".c9r";

	private final CryptorProvider cryptorProvider;

	@Inject
	public Version7Migrator(CryptorProvider cryptorProvider) {
		this.cryptorProvider = cryptorProvider;
	}

	@Override
	public void migrate(Path vaultRoot, String masterkeyFilename, CharSequence passphrase) throws InvalidPassphraseException, UnsupportedVaultFormatException, IOException {
		LOG.info("Upgrading {} from version 6 to version 7.", vaultRoot);
		Path masterkeyFile = vaultRoot.resolve(masterkeyFilename);
		byte[] fileContentsBeforeUpgrade = Files.readAllBytes(masterkeyFile);
		KeyFile keyFile = KeyFile.parse(fileContentsBeforeUpgrade);
		try (Cryptor cryptor = cryptorProvider.createFromKeyFile(keyFile, passphrase, 6)) {
			// create backup, as soon as we know the password was correct:
			Path masterkeyBackupFile = vaultRoot.resolve(masterkeyFilename + BackupUtil.generateFileIdSuffix(fileContentsBeforeUpgrade) + Constants.MASTERKEY_BACKUP_SUFFIX);
			Files.copy(masterkeyFile, masterkeyBackupFile, StandardCopyOption.REPLACE_EXISTING);
			LOG.info("Backed up masterkey from {} to {}.", masterkeyFile.getFileName(), masterkeyBackupFile.getFileName());

			Map<String, String> namePairs = loadShortenedNames(vaultRoot);
			migrateFileNames(namePairs, vaultRoot);

			// TODO remove deprecated .lng from /m/

			// rewrite masterkey file with normalized passphrase:
			byte[] fileContentsAfterUpgrade = cryptor.writeKeysToMasterkeyFile(passphrase, 7).serialize();
			Files.write(masterkeyFile, fileContentsAfterUpgrade, StandardOpenOption.TRUNCATE_EXISTING);
			LOG.info("Updated masterkey.");
		}
		LOG.info("Upgraded {} from version 6 to version 7.", vaultRoot);
	}

	/**
	 * With vault format 7 we increased the file shortening threshold.
	 *
	 * @param vaultRoot
	 * @return
	 * @throws IOException
	 */
	// visible for testing
	Map<String, String> loadShortenedNames(Path vaultRoot) throws IOException {
		Path metadataDir = vaultRoot.resolve("m");
		Map<String, String> result = new HashMap<>();
		ByteBuffer longNameBuffer = ByteBuffer.allocate(FILENAME_BUFFER_SIZE);
		Files.walkFileTree(metadataDir, EnumSet.noneOf(FileVisitOption.class), 3, new SimpleFileVisitor<Path>() {

			@Override
			public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) throws IOException {
				try (SeekableByteChannel ch = Files.newByteChannel(file, StandardOpenOption.READ)) {
					if (ch.size() > longNameBuffer.capacity()) {
						LOG.error("Migrator not suited to handle filenames as large as {}. Aborting without changes.", ch.size());
						throw new IOException("Filename too large for migration: " + file);
					} else {
						longNameBuffer.clear();
						ch.read(longNameBuffer);
						longNameBuffer.flip();
						String longName = UTF_8.decode(longNameBuffer).toString();
						String shortName = file.getFileName().toString();
						result.put(shortName, longName);
						return FileVisitResult.CONTINUE;
					}
				}
			}
		});
		return result;
	}

	void migrateFileNames(Map<String, String> deflatedNames, Path vaultRoot) throws IOException {
		Path dataDir = vaultRoot.resolve("d");
		Files.walkFileTree(dataDir, EnumSet.noneOf(FileVisitOption.class), 3, new SimpleFileVisitor<Path>() {

			@Override
			public FileVisitResult visitFile(Path oldfile, BasicFileAttributes attrs) throws IOException {
				String oldfilename = oldfile.getFileName().toString();
				String newfilename;
				if (deflatedNames.containsKey(oldfilename)) {
					newfilename = deflatedNames.get(oldfilename) + NEW_NORMAL_SUFFIX;
				} else {
					newfilename = oldfilename + NEW_NORMAL_SUFFIX;
				}

				if (newfilename.length() > 254) { // Value of Constants#SHORT_NAMES_MAX_LENGTH as in Vault Format 7
					newfilename = deflate(vaultRoot, newfilename);
				}

				Path newfile = oldfile.resolveSibling(newfilename);
				LOG.info("RENAME {} TO {}", oldfile, newfile);
				return FileVisitResult.CONTINUE;
			}
		});
	}

	String deflate(Path vaultRoot, String longName) throws IOException {
		Path metadataDir = vaultRoot.resolve("m");
		byte[] longFileNameBytes = longName.getBytes(UTF_8);
		byte[] hash = MessageDigestSupplier.SHA1.get().digest(longFileNameBytes);
		String shortName = BASE32.encode(hash) + NEW_SHORTENED_SUFFIX;
		Path metadataFile = metadataDir.resolve(shortName.substring(0, 2)).resolve(shortName.substring(2, 4)).resolve(shortName);
		LOG.info("CREATE {}", metadataFile);
		Files.createDirectories(metadataFile.getParent());
		Files.write(metadataFile, shortName.getBytes(UTF_8));
		return shortName;
	}

}
