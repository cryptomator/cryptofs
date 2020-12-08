package org.cryptomator.cryptofs.migration.v6;

import com.google.common.jimfs.Configuration;
import com.google.common.jimfs.Jimfs;
import org.cryptomator.cryptofs.common.Constants;
import org.cryptomator.cryptofs.common.MasterkeyBackupHelper;
import org.cryptomator.cryptofs.migration.api.Migrator;
import org.cryptomator.cryptofs.mocks.NullSecureRandom;
import org.cryptomator.cryptolib.api.CryptoException;
import org.cryptomator.cryptolib.api.Masterkey;
import org.cryptomator.cryptolib.common.MasterkeyFile;
import org.hamcrest.CoreMatchers;
import org.hamcrest.MatcherAssert;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileSystem;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.text.Normalizer;
import java.text.Normalizer.Form;
import java.util.Optional;

public class Version6MigratorTest {

	private FileSystem fs;
	private Path pathToVault;
	private Path masterkeyFile;
	private SecureRandom csprng = NullSecureRandom.INSTANCE;

	@BeforeEach
	public void setup() throws IOException {
		fs = Jimfs.newFileSystem(Configuration.unix());
		pathToVault = fs.getPath("/vaultDir");
		masterkeyFile = pathToVault.resolve("masterkey.cryptomator");
		//masterkeyBackupFile cannot be set here since we cannot compute a digest from a non-existing file
		Files.createDirectory(pathToVault);
	}

	@AfterEach
	public void teardown() throws IOException {
		fs.close();
	}

	@Test
	public void testMigrate() throws IOException, CryptoException {
		String oldPassword = Normalizer.normalize("ä", Form.NFD);
		String newPassword = Normalizer.normalize("ä", Form.NFC);
		Assertions.assertNotEquals(oldPassword, newPassword);

		Masterkey masterkey = Masterkey.createNew(csprng);
		byte[] beforeMigration = MasterkeyFile.lock(masterkey, oldPassword, new byte[0], 5, csprng);

		Files.write(masterkeyFile, beforeMigration);
		Path masterkeyBackupFile = pathToVault.resolve("masterkey.cryptomator" + MasterkeyBackupHelper.generateFileIdSuffix(beforeMigration) + Constants.MASTERKEY_BACKUP_SUFFIX);

		Migrator migrator = new Version6Migrator(csprng);
		migrator.migrate(pathToVault, null, "masterkey.cryptomator", oldPassword);

		byte[] afterMigration = Files.readAllBytes(masterkeyFile);
		String afterMigrationJson = new String(afterMigration, StandardCharsets.UTF_8);
		MatcherAssert.assertThat(afterMigrationJson, CoreMatchers.containsString("\"version\": 6"));

		try (var keyLoader = MasterkeyFile.withContent(new ByteArrayInputStream(afterMigration)).unlock(newPassword, new byte[0], Optional.of(6))) {
			Assertions.assertNotNull(keyLoader);
		}

		Assertions.assertTrue(Files.exists(masterkeyBackupFile));
		String backedUpJson = Files.readString(masterkeyBackupFile, StandardCharsets.UTF_8);
		MatcherAssert.assertThat(backedUpJson, CoreMatchers.containsString("\"version\": 5"));
	}

}
