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
import org.junit.jupiter.api.function.ThrowingConsumer;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.Mockito;

import java.io.IOException;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import java.net.URI;
import java.nio.file.DirectoryNotEmptyException;
import java.nio.file.FileSystem;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Comparator;
import java.util.Set;
import java.util.stream.Stream;

import static java.nio.file.StandardCopyOption.REPLACE_EXISTING;
import static org.cryptomator.cryptofs.CryptoFileSystemProperties.cryptoFileSystemProperties;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

//For shortening: Since filename encryption increases filename length, 50 cleartext chars are sufficient to reach the threshold
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

	private final static String[] targetFileNamesArray = new String[]{ //
			"target50Chars_56789_123456789_123456789_123456789_", //
			"target15Chars__", //
			"target50Chars_56789_123456789_123456789_123456.txt", //
			"target15C__.txt" //
	};

	static Stream<String> targetFileNames() {
		return Arrays.stream(targetFileNamesArray);
	}

	@ParameterizedTest
	@MethodSource("org.cryptomator.cryptofs.CryptoFileSystemProviderInMemoryIntegrationTest#targetFileNames")
	@Target(ElementType.METHOD)
	@Retention(RetentionPolicy.RUNTIME)
	@interface ParameterizedFileTest {

	}

	@DisplayName("Replace an existing file")
	@ParameterizedFileTest
	public void testReplaceExistingFile(String targetName) throws IOException {
		try (var fs = setupCryptoFs(50, 100, false)) {
			var source = fs.getPath("/source.txt");
			var target = fs.getPath("/" + targetName);
			Files.createFile(source);
			Files.createFile(target);

			assertDoesNotThrow(() -> Files.move(source, target, REPLACE_EXISTING));
			assertTrue(Files.notExists(source));
			assertTrue(Files.exists(target));
		}
	}

	@DisplayName("Replace an existing, empty directory")
	@ParameterizedFileTest
	public void testReplaceExistingDirEmpty(String targetName) throws IOException {
		try (var fs = setupCryptoFs(50, 100, false)) {
			var source = fs.getPath("/sourceDir");
			var target = fs.getPath("/" + targetName);
			Files.createDirectory(source);
			Files.createDirectory(target);

			assertDoesNotThrow(() -> Files.move(source, target, REPLACE_EXISTING));
			assertTrue(Files.notExists(source));
			assertTrue(Files.exists(target));
		}
	}

	/* //TODO https://github.com/cryptomator/cryptofs/issues/177
	@DisplayName("Replace an existing symlink")
	@ParameterizedFileTest
	public void testReplaceExistingSymlink(String targetName) throws IOException {
		try (var fs = setupCryptoFs(50, 100, false)) {
			var source = fs.getPath("/sourceDir");
			var linkedFromSource = fs.getPath("/linkedFromSource.txt");
			var linkedFromSourceContent = "linkedFromSourceContent!";

			var target = fs.getPath("/" + targetName);
			var linkedFromTarget = fs.getPath("/linkedFromTarget.txt");
			var linkedFromTargetContent = "linkedFromTargeContent!";

			Files.createFile(linkedFromSource);
			Files.writeString(linkedFromSource, linkedFromSourceContent, UTF_8);
			Files.createFile(linkedFromTarget);
			Files.writeString(linkedFromTarget, linkedFromTargetContent, UTF_8);

			Files.createSymbolicLink(source, linkedFromSource);
			Files.createSymbolicLink(target, linkedFromTarget);

			assertDoesNotThrow(() -> Files.move(source, target, REPLACE_EXISTING));
			assertTrue(Files.notExists(source));
			assertTrue(Files.exists(target));

			//Assert linked files haven't been changed
			assertTrue(Files.exists(linkedFromSource));
			assertEquals(Files.readString(linkedFromSource, UTF_8), linkedFromSourceContent);
			assertFalse(Files.isSymbolicLink(linkedFromSource));
			assertTrue(Files.isRegularFile(linkedFromSource, LinkOption.NOFOLLOW_LINKS));

			assertTrue(Files.exists(linkedFromTarget));
			assertEquals(Files.readString(linkedFromTarget, UTF_8), linkedFromTargetContent);
			assertFalse(Files.isSymbolicLink(linkedFromTarget));
			assertTrue(Files.isRegularFile(linkedFromTarget, LinkOption.NOFOLLOW_LINKS));

			//Assert link is correct
			assertTrue(Files.isSymbolicLink(target));
			assertTrue(Files.isRegularFile(target /* FOLLOW_LINKS *<remove angle brackets when enabling test>/));
			assertEquals(Files.readSymbolicLink(target), linkedFromSource);
		}
	}*/

	@DisplayName("Delete not existing file")
	@ParameterizedFileTest
	public void testDeleteNotExisting(String targetName) throws IOException {
		try (var fs = setupCryptoFs(50, 100, false)) {
			var file = fs.getPath("/" + targetName);

			assertThrows(NoSuchFileException.class, () -> Files.delete(file));
		}
	}

	@DisplayName("Delete regular file")
	@ParameterizedFileTest
	public void testDeleteFile(String targetName) throws IOException {
		try (var fs = setupCryptoFs(50, 100, false)) {
			var file = fs.getPath("/" + targetName);
			Files.createFile(file);

			assertTrue(Files.exists(file, LinkOption.NOFOLLOW_LINKS));
			assertDoesNotThrow(() -> Files.delete(file));
			assertTrue(Files.notExists(file, LinkOption.NOFOLLOW_LINKS));

			assertThrows(NoSuchFileException.class, () -> Files.delete(file));
		}
	}

	@DisplayName("Delete empty directory that never contained elements")
	@ParameterizedFileTest
	public void testDeleteDirAlwaysEmpty(String targetName) throws IOException {
		try (var fs = setupCryptoFs(50, 100, false)) {
			var file = fs.getPath("/" + targetName);
			Files.createDirectory(file);

			assertTrue(Files.exists(file, LinkOption.NOFOLLOW_LINKS));
			assertDoesNotThrow(() -> Files.delete(file));
			assertTrue(Files.notExists(file, LinkOption.NOFOLLOW_LINKS));

			assertThrows(NoSuchFileException.class, () -> Files.delete(file));
		}
	}

	@DisplayName("Delete directory while and after containing multiple elements")
	@ParameterizedFileTest
	public void testDeleteDirMultiple(String targetName) throws IOException {
		try (var fs = setupCryptoFs(50, 100, false)) {
			var targetDir = fs.getPath("/" + targetName);
			Files.createDirectory(targetDir);

			var nestedFile = targetDir.resolve("nestedFile");
			Files.createFile(nestedFile);
			var nestedDir = targetDir.resolve("nestedDir");
			Files.createDirectory(nestedDir);
			var nestedLink = targetDir.resolve("nestedLink");
			Files.createSymbolicLink(nestedLink, fs.getPath("linkTarget"));

			assertThrows(DirectoryNotEmptyException.class, () -> Files.delete(targetDir));

			assertTrue(Files.exists(targetDir, LinkOption.NOFOLLOW_LINKS));
			assertTrue(Files.exists(nestedFile, LinkOption.NOFOLLOW_LINKS));
			assertTrue(Files.exists(nestedDir, LinkOption.NOFOLLOW_LINKS));
			assertTrue(Files.exists(nestedLink, LinkOption.NOFOLLOW_LINKS));

			assertDoesNotThrow(() -> Files.delete(nestedFile));
			assertDoesNotThrow(() -> Files.delete(nestedDir));
			assertDoesNotThrow(() -> Files.delete(nestedLink));

			assertDoesNotThrow(() -> Files.delete(targetDir));

			assertTrue(Files.notExists(targetDir, LinkOption.NOFOLLOW_LINKS));
			assertTrue(Files.notExists(nestedFile, LinkOption.NOFOLLOW_LINKS));
			assertTrue(Files.notExists(nestedDir, LinkOption.NOFOLLOW_LINKS));
			assertTrue(Files.notExists(nestedLink, LinkOption.NOFOLLOW_LINKS));

			assertThrows(NoSuchFileException.class, () -> Files.delete(targetDir));
		}
	}

	static Stream<Arguments> dirEntries() {
		Stream<ThrowingConsumer<Path>> operations = Stream.of(Files::createFile, //
				Files::createDirectory, //
				nestedElement -> Files.createSymbolicLink(nestedElement, nestedElement.resolveSibling("linkTarget")));
		return operations.flatMap(elementCreator -> targetFileNames().map( //
				s -> Arguments.of(s, elementCreator)) //
		);
	}

	@DisplayName("Delete directory while and after containing one element")
	@ParameterizedTest
	@MethodSource("org.cryptomator.cryptofs.CryptoFileSystemProviderInMemoryIntegrationTest#dirEntries")
	public void testDeleteDirSingle(String targetName, ThrowingConsumer<Path> entryCreator) throws Throwable /* = IOE from entryCreator */ {
		try (var fs = setupCryptoFs(50, 100, false)) {
			var targetDir = fs.getPath("/" + targetName);
			Files.createDirectory(targetDir);

			var nestedElement = targetDir.resolve("nestedElement");
			entryCreator.accept(nestedElement);

			assertThrows(DirectoryNotEmptyException.class, () -> Files.delete(targetDir));
			assertTrue(Files.exists(targetDir, LinkOption.NOFOLLOW_LINKS));
			assertTrue(Files.exists(nestedElement, LinkOption.NOFOLLOW_LINKS));

			assertDoesNotThrow(() -> Files.delete(nestedElement));
			assertDoesNotThrow(() -> Files.delete(targetDir));

			assertTrue(Files.notExists(targetDir, LinkOption.NOFOLLOW_LINKS));
			assertTrue(Files.notExists(nestedElement, LinkOption.NOFOLLOW_LINKS));

			assertThrows(NoSuchFileException.class, () -> Files.delete(targetDir));
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
