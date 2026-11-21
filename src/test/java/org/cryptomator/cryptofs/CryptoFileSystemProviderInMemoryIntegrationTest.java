package org.cryptomator.cryptofs;

import com.google.common.jimfs.Configuration;
import com.google.common.jimfs.Jimfs;
import org.cryptomator.cryptofs.event.DecryptionFailedEvent;
import org.cryptomator.cryptofs.event.FilesystemEvent;
import org.cryptomator.cryptolib.api.Masterkey;
import org.cryptomator.cryptolib.api.MasterkeyLoader;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.URI;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileSystem;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.FileTime;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;
import java.util.stream.Stream;

import static java.nio.file.StandardCopyOption.ATOMIC_MOVE;
import static java.nio.file.StandardCopyOption.REPLACE_EXISTING;
import static java.nio.file.StandardOpenOption.READ;
import static java.nio.file.StandardOpenOption.WRITE;
import static org.cryptomator.cryptofs.CryptoFileSystemProperties.cryptoFileSystemProperties;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class CryptoFileSystemProviderInMemoryIntegrationTest {

	private static final FileTime LONG_AGO = FileTime.from(Instant.parse("2000-01-01T00:00:00Z"));

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
	@DisplayName("Replace an existing, shortened, empty directory")
	public void testReplaceExistingShortenedDirEmpty() throws IOException {
		try (var fs = setupCryptoFs(50, 100, false)) {
			var dirName50Chars = "/target_89_123456789_123456789_123456789_123456789_"; //since filename encryption increases filename length, 50 cleartext chars are sufficient
			var source = fs.getPath("/sourceDir");
			var target = fs.getPath(dirName50Chars);
			Files.createDirectory(source);
			Files.createDirectory(target);
			assertDoesNotThrow(() -> Files.move(source, target, REPLACE_EXISTING));
			assertTrue(Files.notExists(source));
			assertTrue(Files.exists(target));
		}
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

	static Stream<Arguments> shortenedAndUnshortenedNames() {
		var shortName1 = "/source.txt";
		var shortName2 = "/target.txt";
		var longName1 = "/50char1_50char1_50char1_50char1_50char1_50char.txt"; //since filename encryption increases filename length, 50 cleartext chars are sufficient
		var longName2 = "/50char2_50char2_50char2_50char2_50char2_50char.txt";
		return Stream.of(Arguments.of(shortName1, shortName2), Arguments.of(shortName1, longName2), Arguments.of(longName1, shortName2), Arguments.of(longName1, longName2));
	}

	@ParameterizedTest(name = "{0} -> {1}")
	@DisplayName("Replace an opened file")
	@MethodSource("shortenedAndUnshortenedNames")
	public void testReplaceOpenedFile(String sourceName, String targetName) throws IOException {
		try (var fs = setupCryptoFs(50, 100, false)) {
			var source = fs.getPath(sourceName);
			var target = fs.getPath(targetName);
			Files.writeString(source, "new");
			Files.writeString(target, "old-content");

			try (var ch = FileChannel.open(target, READ, WRITE)) {
				assertDoesNotThrow(() -> Files.move(source, target, ATOMIC_MOVE, REPLACE_EXISTING));
				assertEquals("new", Files.readString(target));
				assertEquals("old-content", read(ch));
				ch.write(StandardCharsets.UTF_8.encode("OLD"), 0);
				assertEquals("OLD-content", read(ch));
				assertEquals("new", Files.readString(target));
			}
			assertTrue(Files.notExists(source));
			assertEquals("new", Files.readString(target));
		}
	}

	@ParameterizedTest(name = "{0} -> {1}")
	@DisplayName("Move an opened file and keep writing")
	@MethodSource("shortenedAndUnshortenedNames")
	public void testMoveOpenedFile(String sourceName, String targetName) throws IOException {
		try (var fs = setupCryptoFs(50, 100, false)) {
			var source = fs.getPath(sourceName);
			var target = fs.getPath(targetName);
			Files.writeString(source, "content");

			try (var ch = FileChannel.open(source, READ, WRITE)) {
				Files.move(source, target);
				ch.write(StandardCharsets.UTF_8.encode("C"), 0);
				try (var ch2 = FileChannel.open(target, WRITE)) {
					ch2.write(StandardCharsets.UTF_8.encode("T"), 6);
				}
				assertEquals("ContenT", read(ch));
			}
			assertTrue(Files.notExists(source));
			assertEquals("ContenT", Files.readString(target));
		}
	}

	@Test
	@DisplayName("Replace an opened file by a symlink")
	public void testReplaceOpenedFileBySymlink() throws IOException {
		try (var fs = setupCryptoFs(50, 100, false)) {
			var link = fs.getPath("/link");
			var target = fs.getPath("/target.txt");
			Files.createSymbolicLink(link, fs.getPath("/nowhere"));
			Files.writeString(target, "old-content");

			try (var ch = FileChannel.open(target, READ, WRITE)) {
				Files.move(link, target, REPLACE_EXISTING);
				assertEquals(fs.getPath("/nowhere"), Files.readSymbolicLink(target));
				Files.move(target, fs.getPath("/moved-link"));
				Files.writeString(target, "new");
				assertEquals("old-content", read(ch));
			}
			assertEquals("new", Files.readString(target));
		}
	}

	@ParameterizedTest(name = "{0} -> {1}")
	@DisplayName("Copy over an opened file")
	@MethodSource("shortenedAndUnshortenedNames")
	public void testCopyOverOpenedFile(String sourceName, String targetName) throws IOException {
		try (var fs = setupCryptoFs(50, 100, false)) {
			var source = fs.getPath(sourceName);
			var target = fs.getPath(targetName);
			Files.writeString(source, "new");
			Files.writeString(target, "old-content");

			try (var ch = FileChannel.open(target, READ, WRITE)) {
				Files.copy(source, target, REPLACE_EXISTING);
				assertEquals("new", Files.readString(target));
				assertEquals("old-content", read(ch));
			}
			assertEquals("new", Files.readString(target));
		}
	}

	@ParameterizedTest
	@DisplayName("Open a file whose ciphertext was replaced externally while it was open")
	@ValueSource(strings = {"/a.txt", "/50char1_50char1_50char1_50char1_50char1_50char.txt"})
	public void testOpenExternallyReplacedOpenedFile(String name) throws IOException {
		try (var fs = setupCryptoFs(50, 100, false)) {
			var a = fs.getPath(name);
			var b = fs.getPath("/b.txt");
			Files.write(a, repeat('o', 200_000));
			Files.write(b, repeat('R', 200_000));

			try (var first = FileChannel.open(a, READ)) {
				first.read(ByteBuffer.allocate(4), 0);
				replaceCiphertext(fs, a, ciphertextPath(fs, b));
				try (var second = FileChannel.open(a, READ, WRITE)) {
					assertEquals("oooo", read(first, 98304, 4));
					first.close();
					assertEquals("RRRR", read(second, 98304, 4));
					second.write(ByteBuffer.wrap(repeat('w', 32768)), 98304);
				}
			}
			var expected = repeat('R', 200_000);
			Arrays.fill(expected, 98304, 98304 + 32768, (byte) 'w');
			assertArrayEquals(expected, Files.readAllBytes(a));
		}
	}

	@Test
	@DisplayName("Keep writing to a file whose ciphertext was replaced externally, next to a channel opened afterwards")
	public void testWriteExternallyReplacedOpenedFileNextToLaterChannel() throws IOException {
		try (var fs = setupCryptoFs(50, 100, false)) {
			var a = fs.getPath("/a.txt");
			var b = fs.getPath("/b.txt");
			Files.write(a, repeat('o', 200_000));
			Files.write(b, repeat('R', 200_000));

			try (var first = FileChannel.open(a, READ, WRITE)) {
				first.write(ByteBuffer.wrap(repeat('x', 6 * 32768)), 0);
				var ciphertext = replaceCiphertext(fs, a, ciphertextPath(fs, b));
				Files.setLastModifiedTime(ciphertext, LONG_AGO);
				try (var second = FileChannel.open(a, READ, WRITE)) {
					first.force(true);
					assertEquals(LONG_AGO, Files.getLastModifiedTime(ciphertext));
					first.truncate(100_000);
					assertEquals(200_000, second.size());
					assertEquals(100_000, first.size());
					assertEquals("xxxx", read(first, 99_996, 4));
					first.close();
					assertEquals(LONG_AGO, Files.getLastModifiedTime(ciphertext));
				}
			}
			assertArrayEquals(repeat('R', 200_000), Files.readAllBytes(a));
		}
	}

	@Test
	@DisplayName("Open a file whose ciphertext was replaced externally by another version with the same header")
	public void testOpenOpenedFileReplacedBySameHeader() throws IOException {
		try (var fs = setupCryptoFs(50, 100, false)) {
			var a = fs.getPath("/a.txt");
			Files.write(a, repeat('o', 200_000));
			var snapshot = pathToVault.resolve("snapshot");
			Files.copy(ciphertextPath(fs, a), snapshot);
			try (var ch = FileChannel.open(a, WRITE)) {
				ch.write(ByteBuffer.wrap(repeat('p', 200_000)), 0);
			}

			try (var first = FileChannel.open(a, READ)) {
				first.read(ByteBuffer.allocate(4), 0);
				replaceCiphertext(fs, a, snapshot);
				try (var second = FileChannel.open(a, READ)) {
					assertEquals("oooo", read(second, 0, 4));
				}
			}
		}
	}

	@Test
	@DisplayName("Closing a file whose ciphertext was replaced externally leaves the replacement's last-modified time alone")
	public void testCloseExternallyReplacedOpenedFile() throws IOException {
		try (var fs = setupCryptoFs(50, 100, false)) {
			var a = fs.getPath("/a.txt");
			var b = fs.getPath("/b.txt");
			Files.write(a, repeat('o', 200_000));
			Files.write(b, repeat('R', 200_000));

			Path ciphertext;
			try (var ch = FileChannel.open(a, WRITE)) {
				ch.write(StandardCharsets.UTF_8.encode("abc"), 0);
				ciphertext = replaceCiphertext(fs, a, ciphertextPath(fs, b));
				Files.setLastModifiedTime(ciphertext, LONG_AGO);
			}
			assertEquals(LONG_AGO, Files.getLastModifiedTime(ciphertext));
			assertArrayEquals(repeat('R', 200_000), Files.readAllBytes(a));
		}
	}

	@Test
	@DisplayName("Read the attributes of a file whose ciphertext was replaced externally while it was open")
	public void testAttributesOfExternallyReplacedOpenedFile() throws IOException {
		try (var fs = setupCryptoFs(50, 100, false)) {
			var a = fs.getPath("/a.txt");
			var b = fs.getPath("/b.txt");
			Files.write(a, repeat('o', 200_000));
			Files.write(b, repeat('R', 100_000));

			try (var _ = FileChannel.open(a, READ)) {
				var ciphertext = replaceCiphertext(fs, a, ciphertextPath(fs, b));
				Files.setLastModifiedTime(ciphertext, LONG_AGO);
				assertEquals(100_000, Files.size(a));
				assertEquals(LONG_AGO, Files.getLastModifiedTime(a));
			}
		}
	}

	@Test
	@DisplayName("Report an undecryptable file header to a consumer that may access the file system")
	public void testReportUndecryptableHeader() throws IOException {
		var events = new ArrayList<FilesystemEvent>();
		var fsRef = new AtomicReference<FileSystem>();
		try (var fs = setupCryptoFs(50, 100, false, event -> {
			events.add(event);
			try {
				Files.move(fsRef.get().getPath("/broken.txt"), fsRef.get().getPath("/quarantined.txt"));
			} catch (IOException e) {
				throw new UncheckedIOException(e);
			}
		})) {
			fsRef.set(fs);
			Files.writeString(fs.getPath("/broken.txt"), "content");
			Path ciphertextFile;
			try (var files = Files.walk(pathToVault.resolve("d"))) {
				ciphertextFile = files.filter(Files::isRegularFile).filter(p -> p.getFileName().toString().endsWith(".c9r")).findAny().orElseThrow();
			}
			byte[] ciphertext = Files.readAllBytes(ciphertextFile);
			ciphertext[0] ^= 1;
			Files.write(ciphertextFile, ciphertext);

			assertTimeoutPreemptively(Duration.ofSeconds(10), () -> {
				assertThrows(IOException.class, () -> Files.readString(fs.getPath("/broken.txt")));
			});
			assertEquals(1, events.stream().filter(DecryptionFailedEvent.class::isInstance).count());
			assertTrue(Files.exists(fs.getPath("/quarantined.txt")));
		}
	}

	private static String read(FileChannel ch) throws IOException {
		var buf = ByteBuffer.allocate(100);
		ch.read(buf, 0);
		return StandardCharsets.UTF_8.decode(buf.flip()).toString();
	}

	private static String read(FileChannel ch, long position, int length) throws IOException {
		var buf = ByteBuffer.allocate(length);
		ch.read(buf, position);
		return StandardCharsets.UTF_8.decode(buf.flip()).toString();
	}

	private static byte[] repeat(char c, int count) {
		var bytes = new byte[count];
		Arrays.fill(bytes, (byte) c);
		return bytes;
	}

	private static Path ciphertextPath(FileSystem fs, Path cleartextPath) throws IOException {
		return ((CryptoFileSystem) fs).getCiphertextPath(cleartextPath);
	}

	// replaces the ciphertext like a sync client does
	private static Path replaceCiphertext(FileSystem fs, Path cleartextPath, Path replacement) throws IOException {
		var ciphertext = ciphertextPath(fs, cleartextPath);
		var tmp = ciphertext.resolveSibling("replacement.tmp");
		Files.copy(replacement, tmp);
		Files.move(tmp, ciphertext, REPLACE_EXISTING, ATOMIC_MOVE);
		return ciphertext;
	}

	private FileSystem setupCryptoFs(int ciphertextShorteningThreshold, int maxCleartextFilename, boolean readonly) throws IOException {
		return setupCryptoFs(ciphertextShorteningThreshold, maxCleartextFilename, readonly, event -> {});
	}

	private FileSystem setupCryptoFs(int ciphertextShorteningThreshold, int maxCleartextFilename, boolean readonly, Consumer<FilesystemEvent> eventConsumer) throws IOException {
		byte[] key = new byte[64];
		Arrays.fill(key, (byte) 0x55);
		var keyLoader = mock(MasterkeyLoader.class);
		when(keyLoader.loadKey(any())).thenAnswer(ignored -> new Masterkey(key));
		var properties = CryptoFileSystemProperties.cryptoFileSystemProperties().withKeyLoader(keyLoader).withShorteningThreshold(ciphertextShorteningThreshold).withMaxCleartextNameLength(maxCleartextFilename).withFlags(readonly ? Set.of(CryptoFileSystemProperties.FileSystemFlags.READONLY) : Set.of()).build();
		CryptoFileSystemProvider.initialize(pathToVault, properties, URI.create("test:key"));
		URI fsUri = CryptoFileSystemUri.create(pathToVault);
		return FileSystems.newFileSystem(fsUri, cryptoFileSystemProperties().withKeyLoader(keyLoader).withFilesystemEventConsumer(eventConsumer).build());
	}

}
