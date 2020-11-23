package org.cryptomator.cryptofs.migration.v8;

import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.google.common.jimfs.Configuration;
import com.google.common.jimfs.Jimfs;
import org.cryptomator.cryptofs.migration.api.Migrator;
import org.cryptomator.cryptofs.mocks.NullSecureRandom;
import org.cryptomator.cryptolib.Cryptors;
import org.cryptomator.cryptolib.api.CryptorProvider;
import org.cryptomator.cryptolib.api.KeyFile;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.FileSystem;
import java.nio.file.Files;
import java.nio.file.Path;

public class Version8MigratorTest {

	private FileSystem fs;
	private Path pathToVault;
	private Path masterkeyFile;
	private Path vaultConfigFile;
	private CryptorProvider cryptorProvider;

	@BeforeEach
	public void setup() throws IOException {
		cryptorProvider = Cryptors.version1(NullSecureRandom.INSTANCE);
		fs = Jimfs.newFileSystem(Configuration.unix());
		pathToVault = fs.getPath("/vaultDir");
		masterkeyFile = pathToVault.resolve("masterkey.cryptomator");
		vaultConfigFile = pathToVault.resolve("vaultconfig.cryptomator");
		Files.createDirectory(pathToVault);
	}

	@AfterEach
	public void teardown() throws IOException {
		fs.close();
	}

	@Test
	public void testMigrate() throws IOException {
		KeyFile beforeMigration = cryptorProvider.createNew().writeKeysToMasterkeyFile("topsecret", 7);
		Assumptions.assumeTrue(beforeMigration.getVersion() == 7);
		Assumptions.assumeFalse(Files.exists(vaultConfigFile));
		Files.write(masterkeyFile, beforeMigration.serialize());

		Migrator migrator = new Version8Migrator(cryptorProvider);
		migrator.migrate(pathToVault, masterkeyFile.getFileName().toString(), "topsecret");

		KeyFile afterMigration = KeyFile.parse(Files.readAllBytes(masterkeyFile));
		Assertions.assertEquals(999, afterMigration.getVersion());
		Assertions.assertTrue(Files.exists(vaultConfigFile));
		DecodedJWT token = JWT.decode(Files.readString(vaultConfigFile));
		Assertions.assertNotNull(token.getId());
		Assertions.assertEquals("MASTERKEY_FILE", token.getKeyId());
		Assertions.assertEquals(8, token.getClaim("format").asInt());
		Assertions.assertEquals("SIV_CTRMAC", token.getClaim("ciphermode").asString());
		Assertions.assertEquals(220, token.getClaim("maxFileNameLen").asInt());
	}

}