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
		Path dataFile2 = dataDir.resolve("00/000000000000000000000000000000/1C6637A8F2E1F75E06FF9984894D6BD16A3A36A9.lng"); // 222
		Path metaFile2 = metaDir.resolve("1C/66/1C6637A8F2E1F75E06FF9984894D6BD16A3A36A9.lng");
		Path dataFile3 = dataDir.resolve("00/000000000000000000000000000000/0B51FC45F30A0C3027F2B4C4698C5EFCA3C62FE0.lng"); // 129 chars 33333...
		Path metaFile3 = metaDir.resolve("0B/51/0B51FC45F30A0C3027F2B4C4698C5EFCA3C62FE0.lng");
		Path dataFile4 = dataDir.resolve("00/000000000000000000000000000000/CAF8F7708CBF2FD3E735A0C765EBB8E0B879360A.lng"); // 130 chars 44444...
		Path metaFile4 = metaDir.resolve("CA/F8/CAF8F7708CBF2FD3E735A0C765EBB8E0B879360A.lng");
		Path dataFile5 = dataDir.resolve("00/000000000000000000000000000000/1CB1308D10CF786A827C91EEC1FF7B08D91ACAD6.lng"); // 250 chars 55555...
		Path metaFile5 = metaDir.resolve("1C/B1/1CB1308D10CF786A827C91EEC1FF7B08D91ACAD6.lng");
		Path dataFile6 = dataDir.resolve("00/000000000000000000000000000000/C7D6C6201B5344583A9ED2D8F5C3239CCF666230.lng"); // 251 chars 66666...
		Path metaFile6 = metaDir.resolve("C7/D6/C7D6C6201B5344583A9ED2D8F5C3239CCF666230.lng");
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
		Assertions.assertEquals(Strings.repeat("2", 3), namePairs.get("1C6637A8F2E1F75E06FF9984894D6BD16A3A36A9.lng"));
		Assertions.assertEquals(Strings.repeat("3", 129), namePairs.get("0B51FC45F30A0C3027F2B4C4698C5EFCA3C62FE0.lng"));
		Assertions.assertEquals(Strings.repeat("4", 130), namePairs.get("CAF8F7708CBF2FD3E735A0C765EBB8E0B879360A.lng"));
		Assertions.assertEquals(Strings.repeat("5", 250), namePairs.get("1CB1308D10CF786A827C91EEC1FF7B08D91ACAD6.lng"));
		Assertions.assertEquals(Strings.repeat("6", 251), namePairs.get("C7D6C6201B5344583A9ED2D8F5C3239CCF666230.lng"));
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
