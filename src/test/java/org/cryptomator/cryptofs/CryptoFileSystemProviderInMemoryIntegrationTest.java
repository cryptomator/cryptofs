package org.cryptomator.cryptofs;

import com.google.common.jimfs.Configuration;
import com.google.common.jimfs.Jimfs;
import org.cryptomator.cryptolib.api.Masterkey;
import org.cryptomator.cryptolib.api.MasterkeyLoader;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.io.IOException;
import java.net.URI;
import java.nio.file.FileSystem;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Comparator;
import java.util.Set;

import static java.nio.file.StandardCopyOption.REPLACE_EXISTING;
import static org.cryptomator.cryptofs.CryptoFileSystemProperties.cryptoFileSystemProperties;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class CryptoFileSystemProviderInMemoryIntegrationTest {

	private static FileSystem tmpFs;
	private static Path pathToVault;

	@BeforeAll
	public static void beforeAll() {
		tmpFs = Jimfs.newFileSystem(Configuration.unix());
		pathToVault = tmpFs.getPath("/vault");
	}

	@BeforeEach
	public void beforeEach() throws IOException {
		Files.createDirectory(pathToVault);
	}

	@AfterEach
	public void afterEach() throws IOException {
		try (var paths = Files.walk(pathToVault)) {
			var nodes = paths.sorted(Comparator.reverseOrder()).toList();
			for (var node : nodes) {
				Files.delete(node);
			}
		}
	}

	@AfterAll
	public static void afterAll() throws IOException {
		tmpFs.close();
	}

	@Test
	@DisplayName("Replace an existing, shortened file")
	public void testReplaceExistingShortenedFile() throws IOException {
		try (var fs = setupCryptoFs(50, 100, false)) {
			var fiftyCharName2 = "/50char2_50char2_50char2_50char2_50char2_50char.txt"; //since filename encryption increases filename length, 50 cleartext chars are sufficient
			var source = fs.getPath("/source.txt");
			var target = fs.getPath(fiftyCharName2);
			Files.createFile(source);
			Files.createFile(target);

			assertDoesNotThrow(() -> Files.move(source, target, REPLACE_EXISTING));
			assertTrue(Files.notExists(source));
			assertTrue(Files.exists(target));
		}
	}

	private FileSystem setupCryptoFs(int ciphertextShorteningThreshold, int maxCleartextFilename, boolean readonly) throws IOException {
		byte[] key = new byte[64];
		Arrays.fill(key, (byte) 0x55);
		var keyLoader = Mockito.mock(MasterkeyLoader.class);
		Mockito.when(keyLoader.loadKey(Mockito.any())).thenAnswer(ignored -> new Masterkey(key));
		var properties = CryptoFileSystemProperties.cryptoFileSystemProperties().withKeyLoader(keyLoader).withShorteningThreshold(ciphertextShorteningThreshold).withMaxCleartextNameLength(maxCleartextFilename).withFlags(readonly ? Set.of(CryptoFileSystemProperties.FileSystemFlags.READONLY) : Set.of()).build();
		CryptoFileSystemProvider.initialize(pathToVault, properties, URI.create("test:key"));
		URI fsUri = CryptoFileSystemUri.create(pathToVault);
		return FileSystems.newFileSystem(fsUri, cryptoFileSystemProperties().withKeyLoader(keyLoader).build());
	}

}
