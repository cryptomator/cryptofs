package org.cryptomator.cryptofs.migration.v7;

import com.google.common.jimfs.Configuration;
import com.google.common.jimfs.Jimfs;
import org.cryptomator.cryptofs.migration.api.Migrator;
import org.cryptomator.cryptofs.mocks.NullSecureRandom;
import org.cryptomator.cryptolib.api.CryptoException;
import org.cryptomator.cryptolib.api.Masterkey;
import org.cryptomator.cryptolib.common.MasterkeyFileAccess;
import org.hamcrest.CoreMatchers;
import org.hamcrest.MatcherAssert;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileSystem;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;

public class Version7MigratorTest {

	private FileSystem fs;
	private Path vaultRoot;
	private Path dataDir;
	private Path metaDir;
	private Path masterkeyFile;
	private SecureRandom csprng = NullSecureRandom.INSTANCE;

	@BeforeEach
	public void setup() throws IOException {
		fs = Jimfs.newFileSystem(Configuration.unix());
		vaultRoot = fs.getPath("/vaultDir");
		dataDir = vaultRoot.resolve("d");
		metaDir = vaultRoot.resolve("m");
		masterkeyFile = vaultRoot.resolve("masterkey.cryptomator");
		Files.createDirectory(vaultRoot);
		Files.createDirectory(dataDir);
		Files.createDirectory(metaDir);

		Masterkey masterkey = Masterkey.generate(csprng);
		MasterkeyFileAccess masterkeyFileAccess = new MasterkeyFileAccess(new byte[0], csprng);
		masterkeyFileAccess.persist(masterkey, masterkeyFile, "test", 6);
	}

	@AfterEach
	public void teardown() throws IOException {
		fs.close();
	}

	@Test
	public void testKeyfileGetsUpdates() throws CryptoException, IOException {
		Migrator migrator = new Version7Migrator(csprng);
		migrator.migrate(vaultRoot, null, "masterkey.cryptomator", "test");

		String migrated = Files.readString(masterkeyFile, StandardCharsets.UTF_8);
		MatcherAssert.assertThat(migrated, CoreMatchers.containsString("\"version\": 7"));
	}

	@Test
	public void testMDirectoryGetsDeleted() throws CryptoException, IOException {
		Migrator migrator = new Version7Migrator(csprng);
		migrator.migrate(vaultRoot, null, "masterkey.cryptomator", "test");

		Assertions.assertFalse(Files.exists(metaDir));
	}

	@Test
	public void testMigrationFailsIfEncounteringUnsyncediCloudContent() throws IOException {
		Path dir = dataDir.resolve("AA/BBBBBCCCCCDDDDDEEEEEFFFFFGGGGG");
		Files.createDirectories(dir);
		Path fileBeforeMigration = dir.resolve("MZUWYZLOMFWWK===.icloud");
		Files.createFile(fileBeforeMigration);

		Migrator migrator = new Version7Migrator(csprng);

		IOException e = Assertions.assertThrows(PreMigrationVisitor.PreMigrationChecksFailedException.class, () -> {
			migrator.migrate(vaultRoot, null, "masterkey.cryptomator", "test");
		});
		Assertions.assertTrue(e.getMessage().contains("MZUWYZLOMFWWK===.icloud"));
	}

	@Test
	public void testMigrationOfNormalFile() throws CryptoException, IOException {
		Path dir = dataDir.resolve("AA/BBBBBCCCCCDDDDDEEEEEFFFFFGGGGG");
		Files.createDirectories(dir);
		Path fileBeforeMigration = dir.resolve("MZUWYZLOMFWWK===");
		Path fileAfterMigration = dir.resolve("ZmlsZW5hbWU=.c9r");
		Files.createFile(fileBeforeMigration);

		Migrator migrator = new Version7Migrator(csprng);
		migrator.migrate(vaultRoot, null, "masterkey.cryptomator", "test");

		Assertions.assertFalse(Files.exists(fileBeforeMigration));
		Assertions.assertTrue(Files.exists(fileAfterMigration));
	}

	@Test
	public void testMigrationOfNormalDirectory() throws CryptoException, IOException {
		Path dir = dataDir.resolve("AA/BBBBBCCCCCDDDDDEEEEEFFFFFGGGGG");
		Files.createDirectories(dir);
		Path fileBeforeMigration = dir.resolve("0MZUWYZLOMFWWK===");
		Path fileAfterMigration = dir.resolve("ZmlsZW5hbWU=.c9r/dir.c9r");
		Files.createFile(fileBeforeMigration);

		Migrator migrator = new Version7Migrator(csprng);
		migrator.migrate(vaultRoot, null, "masterkey.cryptomator", "test");

		Assertions.assertFalse(Files.exists(fileBeforeMigration));
		Assertions.assertTrue(Files.exists(fileAfterMigration));
	}

	@Test
	public void testMigrationOfNormalSymlink() throws CryptoException, IOException {
		Path dir = dataDir.resolve("AA/BBBBBCCCCCDDDDDEEEEEFFFFFGGGGG");
		Files.createDirectories(dir);
		Path fileBeforeMigration = dir.resolve("1SMZUWYZLOMFWWK===");
		Path fileAfterMigration = dir.resolve("ZmlsZW5hbWU=.c9r/symlink.c9r");
		Files.createFile(fileBeforeMigration);

		Migrator migrator = new Version7Migrator(csprng);
		migrator.migrate(vaultRoot, null, "masterkey.cryptomator", "test");

		Assertions.assertFalse(Files.exists(fileBeforeMigration));
		Assertions.assertTrue(Files.exists(fileAfterMigration));
	}

}
