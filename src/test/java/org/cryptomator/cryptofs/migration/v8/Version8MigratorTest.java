package org.cryptomator.cryptofs.migration.v8;

import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.google.common.jimfs.Configuration;
import com.google.common.jimfs.Jimfs;
import org.cryptomator.cryptofs.migration.api.Migrator;
import org.cryptomator.cryptofs.mocks.NullSecureRandom;
import org.cryptomator.cryptolib.Cryptors;
import org.cryptomator.cryptolib.api.CryptoException;
import org.cryptomator.cryptolib.api.CryptorProvider;
import org.cryptomator.cryptolib.api.Masterkey;
import org.cryptomator.cryptolib.common.MasterkeyFile;
import org.hamcrest.CoreMatchers;
import org.hamcrest.MatcherAssert;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileSystem;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;

public class Version8MigratorTest {

	private FileSystem fs;
	private Path pathToVault;
	private Path masterkeyFile;
	private Path vaultConfigFile;
	private SecureRandom csprng = NullSecureRandom.INSTANCE;

	@BeforeEach
	public void setup() throws IOException {
		fs = Jimfs.newFileSystem(Configuration.unix());
		pathToVault = fs.getPath("/vaultDir");
		masterkeyFile = pathToVault.resolve("masterkey.cryptomator");
		vaultConfigFile = pathToVault.resolve("vault.cryptomator");
		Files.createDirectory(pathToVault);
	}

	@AfterEach
	public void teardown() throws IOException {
		fs.close();
	}

	@Test
	public void testMigrate() throws CryptoException, IOException {
		Masterkey masterkey = Masterkey.createNew(csprng);
		byte[] unmigrated = MasterkeyFile.lock(masterkey, "topsecret", new byte[0], 7, csprng);
		Assumptions.assumeFalse(Files.exists(vaultConfigFile));
		Files.write(masterkeyFile, unmigrated);

		Migrator migrator = new Version8Migrator(csprng);
		migrator.migrate(pathToVault, "vault.cryptomator", "masterkey.cryptomator", "topsecret");

		String migrated = Files.readString(masterkeyFile, StandardCharsets.UTF_8);
		MatcherAssert.assertThat(migrated, CoreMatchers.containsString("\"version\": 999"));
		Assertions.assertTrue(Files.exists(vaultConfigFile));
		DecodedJWT token = JWT.decode(Files.readString(vaultConfigFile));
		Assertions.assertNotNull(token.getId());
		Assertions.assertEquals("MASTERKEY_FILE", token.getKeyId());
		Assertions.assertEquals(8, token.getClaim("format").asInt());
		Assertions.assertEquals("SIV_CTRMAC", token.getClaim("cipherCombo").asString());
		Assertions.assertEquals(220, token.getClaim("maxFilenameLen").asInt());
	}

}