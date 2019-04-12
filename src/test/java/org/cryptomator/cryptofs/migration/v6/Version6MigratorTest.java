package org.cryptomator.cryptofs.migration.v6;

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
import java.text.Normalizer;
import java.text.Normalizer.Form;

public class Version6MigratorTest {

	private FileSystem fs;
	private Path pathToVault;
	private Path masterkeyFile;
	private Path masterkeyBackupFile;
	private CryptorProvider cryptorProvider;

	@BeforeEach
	public void setup() throws IOException {
		cryptorProvider = Cryptors.version1(NullSecureRandom.INSTANCE);
		fs = Jimfs.newFileSystem(Configuration.unix());
		pathToVault = fs.getPath("/vaultDir");
		masterkeyFile = pathToVault.resolve("masterkey.cryptomator");
		masterkeyBackupFile = pathToVault.resolve("masterkey.cryptomator.bkup");
		Files.createDirectory(pathToVault);
	}

	@AfterEach
	public void teardown() throws IOException {
		fs.close();
	}

	@Test
	public void testMigrate() throws IOException {
		String oldPassword = Normalizer.normalize("ä", Form.NFD);
		String newPassword = Normalizer.normalize("ä", Form.NFC);
		Assertions.assertNotEquals(oldPassword, newPassword);

		KeyFile beforeMigration = cryptorProvider.createNew().writeKeysToMasterkeyFile(oldPassword, 5);
		Assertions.assertEquals(5, beforeMigration.getVersion());
		Files.write(masterkeyFile, beforeMigration.serialize());

		Migrator migrator = new Version6Migrator(cryptorProvider);
		migrator.migrate(pathToVault, "masterkey.cryptomator", oldPassword);

		KeyFile afterMigration = KeyFile.parse(Files.readAllBytes(masterkeyFile));
		Assertions.assertEquals(6, afterMigration.getVersion());
		try (Cryptor cryptor = cryptorProvider.createFromKeyFile(afterMigration, newPassword, 6)) {
			Assertions.assertNotNull(cryptor);
		}

		Assertions.assertTrue(Files.exists(masterkeyBackupFile));
		KeyFile backupKey = KeyFile.parse(Files.readAllBytes(masterkeyBackupFile));
		Assertions.assertEquals(5, backupKey.getVersion());
	}

}
