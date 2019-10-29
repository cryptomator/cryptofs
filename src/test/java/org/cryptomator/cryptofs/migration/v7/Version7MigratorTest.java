package org.cryptomator.cryptofs.migration.v7;

import com.google.common.jimfs.Configuration;
import com.google.common.jimfs.Jimfs;
import org.cryptomator.cryptofs.migration.api.Migrator;
import org.cryptomator.cryptofs.mocks.NullSecureRandom;
import org.cryptomator.cryptolib.Cryptors;
import org.cryptomator.cryptolib.api.Cryptor;
import org.cryptomator.cryptolib.api.CryptorProvider;
import org.cryptomator.cryptolib.api.KeyFile;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.FileSystem;
import java.nio.file.Files;
import java.nio.file.Path;

public class Version7MigratorTest {

	private FileSystem fs;
	private Path vaultRoot;
	private Path dataDir;
	private Path metaDir;
	private Path masterkeyFile;
	private CryptorProvider cryptorProvider;

	@BeforeEach
	public void setup() throws IOException {
		cryptorProvider = Cryptors.version1(NullSecureRandom.INSTANCE);
		fs = Jimfs.newFileSystem(Configuration.unix());
		vaultRoot = fs.getPath("/vaultDir");
		dataDir = vaultRoot.resolve("d");
		metaDir = vaultRoot.resolve("m");
		masterkeyFile = vaultRoot.resolve("masterkey.cryptomator");
		Files.createDirectory(vaultRoot);
		Files.createDirectory(dataDir);
		Files.createDirectory(metaDir);
		try (Cryptor cryptor = cryptorProvider.createNew()) {
			KeyFile keyFile = cryptor.writeKeysToMasterkeyFile("test", 6);
			Files.write(masterkeyFile, keyFile.serialize());
		}
	}

	@AfterEach
	public void teardown() throws IOException {
		fs.close();
	}

	@Test
	public void testKeyfileGetsUpdates() throws IOException {
		KeyFile beforeMigration = KeyFile.parse(Files.readAllBytes(masterkeyFile));
		Assertions.assertEquals(6, beforeMigration.getVersion());

		Migrator migrator = new Version7Migrator(cryptorProvider);
		migrator.migrate(vaultRoot, "masterkey.cryptomator", "test");

		KeyFile afterMigration = KeyFile.parse(Files.readAllBytes(masterkeyFile));
		Assertions.assertEquals(7, afterMigration.getVersion());
	}

	@Test
	public void testMDirectoryGetsDeleted() throws IOException {
		Migrator migrator = new Version7Migrator(cryptorProvider);
		migrator.migrate(vaultRoot, "masterkey.cryptomator", "test");
		
		Assertions.assertFalse(Files.exists(metaDir));
	}

	@Test
	public void testMigrationOfNormalFile() throws IOException {
		Path dir = dataDir.resolve("AA/BBBBBCCCCCDDDDDEEEEEFFFFFGGGGG");
		Files.createDirectories(dir);
		Path fileBeforeMigration = dir.resolve("MZUWYZLOMFWWK===");
		Path fileAfterMigration = dir.resolve("ZmlsZW5hbWU=.c9r");
		Files.createFile(fileBeforeMigration);

		Migrator migrator = new Version7Migrator(cryptorProvider);
		migrator.migrate(vaultRoot, "masterkey.cryptomator", "test");

		Assertions.assertFalse(Files.exists(fileBeforeMigration));
		Assertions.assertTrue(Files.exists(fileAfterMigration));
	}

	@Test
	public void testMigrationOfNormalDirectory() throws IOException {
		Path dir = dataDir.resolve("AA/BBBBBCCCCCDDDDDEEEEEFFFFFGGGGG");
		Files.createDirectories(dir);
		Path fileBeforeMigration = dir.resolve("0MZUWYZLOMFWWK===");
		Path fileAfterMigration = dir.resolve("ZmlsZW5hbWU=.c9r/dir.c9r");
		Files.createFile(fileBeforeMigration);

		Migrator migrator = new Version7Migrator(cryptorProvider);
		migrator.migrate(vaultRoot, "masterkey.cryptomator", "test");

		Assertions.assertFalse(Files.exists(fileBeforeMigration));
		Assertions.assertTrue(Files.exists(fileAfterMigration));
	}

	@Test
	public void testMigrationOfNormalSymlink() throws IOException {
		Path dir = dataDir.resolve("AA/BBBBBCCCCCDDDDDEEEEEFFFFFGGGGG");
		Files.createDirectories(dir);
		Path fileBeforeMigration = dir.resolve("1SMZUWYZLOMFWWK===");
		Path fileAfterMigration = dir.resolve("ZmlsZW5hbWU=.c9r/symlink.c9r");
		Files.createFile(fileBeforeMigration);

		Migrator migrator = new Version7Migrator(cryptorProvider);
		migrator.migrate(vaultRoot, "masterkey.cryptomator", "test");

		Assertions.assertFalse(Files.exists(fileBeforeMigration));
		Assertions.assertTrue(Files.exists(fileAfterMigration));
	}

}
