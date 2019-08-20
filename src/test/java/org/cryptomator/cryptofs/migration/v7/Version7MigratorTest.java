package org.cryptomator.cryptofs.migration.v7;

import com.google.common.base.Strings;
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
import java.nio.charset.StandardCharsets;
import java.nio.file.FileSystem;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;

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
		Path dataFile1 = dataDir.resolve("00/000000000000000000000000000000/111");
		Path dataFile2 = dataDir.resolve("00/000000000000000000000000000000/1c6637a8f2e1f75e06ff9984894d6bd16a3a36a9.lng"); // 222
		Path metaFile2 = metaDir.resolve("1c/66/1c6637a8f2e1f75e06ff9984894d6bd16a3a36a9.lng");
		Path dataFile3 = dataDir.resolve("00/000000000000000000000000000000/0b51fc45f30a0c3027f2b4c4698c5efca3c62fe0.lng"); // 129 chars 33333...
		Path metaFile3 = metaDir.resolve("0b/51/0b51fc45f30a0c3027f2b4c4698c5efca3c62fe0.lng");
		Path dataFile4 = dataDir.resolve("00/000000000000000000000000000000/caf8f7708cbf2fd3e735a0c765ebb8e0b879360a.lng"); // 130 chars 44444...
		Path metaFile4 = metaDir.resolve("ca/f8/caf8f7708cbf2fd3e735a0c765ebb8e0b879360a.lng");
		Path dataFile5 = dataDir.resolve("00/000000000000000000000000000000/1cb1308d10cf786a827c91eec1ff7b08d91acad6.lng"); // 250 chars 55555...
		Path metaFile5 = metaDir.resolve("1c/b1/1cb1308d10cf786a827c91eec1ff7b08d91acad6.lng");
		Path dataFile6 = dataDir.resolve("00/000000000000000000000000000000/c7d6c6201b5344583a9ed2d8f5c3239ccf666230.lng"); // 251 chars 66666...
		Path metaFile6 = metaDir.resolve("c7/d6/c7d6c6201b5344583a9ed2d8f5c3239ccf666230.lng");
		Files.createDirectories(dataDir.resolve("00/000000000000000000000000000000"));
		Files.createFile(dataFile1);
		Files.createFile(dataFile2);
		Files.createFile(dataFile3);
		Files.createFile(dataFile4);
		Files.createFile(dataFile5);
		Files.createFile(dataFile6);
		Files.createDirectories(metaFile2.getParent());
		Files.createDirectories(metaFile3.getParent());
		Files.createDirectories(metaFile4.getParent());
		Files.createDirectories(metaFile5.getParent());
		Files.createDirectories(metaFile6.getParent());
		Files.write(metaFile2, Strings.repeat("2", 3).getBytes(StandardCharsets.UTF_8));
		Files.write(metaFile3, Strings.repeat("3", 129).getBytes(StandardCharsets.UTF_8));
		Files.write(metaFile4, Strings.repeat("4", 130).getBytes(StandardCharsets.UTF_8));
		Files.write(metaFile5, Strings.repeat("5", 250).getBytes(StandardCharsets.UTF_8));
		Files.write(metaFile6, Strings.repeat("6", 251).getBytes(StandardCharsets.UTF_8));
	}

	@AfterEach
	public void teardown() throws IOException {
		fs.close();
	}

	@Test
	public void testLoadShortenedNames() throws IOException {
		Version7Migrator migrator = new Version7Migrator(cryptorProvider);

		Map<String, String> namePairs = migrator.loadShortenedNames(vaultRoot);

		// <= 254 chars should be unshortened:
		Assertions.assertEquals(Strings.repeat("2", 3), namePairs.get("1c6637a8f2e1f75e06ff9984894d6bd16a3a36a9.lng"));
		Assertions.assertEquals(Strings.repeat("3", 129), namePairs.get("0b51fc45f30a0c3027f2b4c4698c5efca3c62fe0.lng"));
		Assertions.assertEquals(Strings.repeat("4", 130), namePairs.get("caf8f7708cbf2fd3e735a0c765ebb8e0b879360a.lng"));
		Assertions.assertEquals(Strings.repeat("5", 250), namePairs.get("1cb1308d10cf786a827c91eec1ff7b08d91acad6.lng"));
		// > 254 chars should remain shortened:
		Assertions.assertFalse(namePairs.containsKey("c7d6c6201b5344583a9ed2d8f5c3239ccf666230.lng"));
	}

	@Test
	public void testMigration() throws IOException {
		KeyFile beforeMigration = KeyFile.parse(Files.readAllBytes(masterkeyFile));
		Assertions.assertEquals(6, beforeMigration.getVersion());

		Migrator migrator = new Version7Migrator(cryptorProvider);
		migrator.migrate(vaultRoot, "masterkey.cryptomator", "test");

		KeyFile afterMigration = KeyFile.parse(Files.readAllBytes(masterkeyFile));
		Assertions.assertEquals(7, afterMigration.getVersion());
	}

}
