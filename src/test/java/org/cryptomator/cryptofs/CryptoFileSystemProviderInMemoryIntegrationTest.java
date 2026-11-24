package org.cryptomator.cryptofs;

import com.google.common.jimfs.Configuration;
import com.google.common.jimfs.Jimfs;
import org.cryptomator.cryptofs.event.DecryptionFailedEvent;
import org.cryptomator.cryptofs.event.FileWriteConflictEvent;
import org.cryptomator.cryptofs.event.FilesystemEvent;
import org.cryptomator.cryptolib.api.Masterkey;
import org.cryptomator.cryptolib.api.MasterkeyLoader;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.URI;
import java.nio.ByteBuffer;
import java.nio.channels.Channels;
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
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.FutureTask;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;
import java.util.stream.Stream;

import static java.nio.file.StandardCopyOption.ATOMIC_MOVE;
import static java.nio.file.StandardCopyOption.REPLACE_EXISTING;
import static java.nio.file.StandardOpenOption.APPEND;
import static java.nio.file.StandardOpenOption.READ;
import static java.nio.file.StandardOpenOption.WRITE;
import static org.awaitility.Awaitility.await;
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
	private static final int CHUNK = 32 * 1024;
	private static final int CIPHERTEXT_CHUNK = CHUNK + 28;
	private static final int HEADER_SIZE = 68;

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

	@Test
	@DisplayName("A truncate to a chunk boundary keeps an unsaved write to an earlier chunk")
	public void testBoundaryTruncateKeepsUnsavedEarlierWrite() throws IOException {
		try (var fs = setupCryptoFs(50, 100, false)) {
			var file = fs.getPath("/a.txt");
			Files.write(file, repeat('o', 3 * CHUNK));

			try (var ch = FileChannel.open(file, READ, WRITE)) {
				ch.write(StandardCharsets.UTF_8.encode("x"), 5);
				ch.truncate(CHUNK);
			}

			var expected = repeat('o', CHUNK);
			expected[5] = 'x';
			assertArrayEquals(expected, Files.readAllBytes(file));
		}
	}

	@Test
	@DisplayName("Saving through a ciphertext handle an interrupt closed fails with an IOException")
	public void testSaveThroughHandleClosedByInterrupt() throws IOException {
		try (var fs = setupCryptoFs(50, 100, false)) {
			var file = fs.getPath("/a.txt");
			Files.write(file, repeat('o', CHUNK));

			try (var ch = FileChannel.open(file, READ, WRITE)) {
				ch.write(StandardCharsets.UTF_8.encode("x"), 5);
				Thread.currentThread().interrupt();
				try {
					assertThrows(IOException.class, () -> ch.force(false)); // the interrupt closes the ciphertext handle
				} finally {
					Thread.interrupted();
				}

				assertThrows(IOException.class, () -> ch.force(false));
				assertThrows(IOException.class, ch::close); // closing fails like the force, as the edit can't be saved
			}
		}
	}

	@Nested
	@DisplayName("Ciphertext changed in place while the file is open")
	class ChangedInPlace {

		private final List<FilesystemEvent> events = new CopyOnWriteArrayList<>();

		@ParameterizedTest(name = "second edit of {0} bytes")
		@ValueSource(ints = {0, 1, CHUNK})
		@DisplayName("A dirty chunk is not saved over the new version, also after a second edit")
		public void testDirtyChunkKeepsNewVersion(int secondEditLength) throws IOException {
			try (var fs = setupCryptoFs(50, 100, false, events::add)) {
				var file = fs.getPath("/a.txt");
				var newer = olderOnDiskReturningNewer(fs, file, repeat('o', 3 * CHUNK), repeat('n', 3 * CHUNK));
				var ciphertext = ciphertextPath(fs, file);

				try (var ch = FileChannel.open(file, READ, WRITE)) {
					ch.write(StandardCharsets.UTF_8.encode("x"), 100);
					overwriteInPlace(ciphertext, newer);
					if (secondEditLength > 0) { // the dirty chunk keeps the baseline of the version it was loaded from
						ch.write(ByteBuffer.wrap(repeat('y', secondEditLength)), 0);
					}
					assertThrows(IOException.class, ch::close);
				}

				var event = awaitConflictEvent(events);
				assertEquals(ciphertext, event.ciphertextPath());
				assertEquals("/a.txt", event.cleartextPath());
				assertArrayEquals(newer, Files.readAllBytes(ciphertext));
				assertArrayEquals(repeat('n', 3 * CHUNK), Files.readAllBytes(file));
			}
		}

		@Test
		@DisplayName("A dirty chunk is not saved under the old header")
		public void testDirtyChunkKeepsOtherHeader() throws IOException {
			try (var fs = setupCryptoFs(50, 100, false, events::add)) {
				var file = fs.getPath("/a.txt");
				Files.write(file, repeat('o', 3 * CHUNK));
				var other = ciphertextOfOtherFile(fs, repeat('R', 3 * CHUNK));
				var ciphertext = ciphertextPath(fs, file);

				try (var ch = FileChannel.open(file, READ, WRITE)) {
					ch.write(StandardCharsets.UTF_8.encode("x"), 100);
					overwriteInPlace(ciphertext, other);
					assertThrows(IOException.class, ch::close);
				}

				awaitConflictEvent(events);
				assertArrayEquals(other, Files.readAllBytes(ciphertext));
				assertArrayEquals(repeat('R', 3 * CHUNK), Files.readAllBytes(file));
			}
		}

		@Test
		@DisplayName("The conflict event of a shortened name carries its contents file")
		public void testConflictEventOfShortenedName() throws IOException {
			try (var fs = setupCryptoFs(50, 100, false, events::add)) {
				var name = "/50char1_50char1_50char1_50char1_50char1_50char.txt";
				var file = fs.getPath(name);
				var newer = olderOnDiskReturningNewer(fs, file, repeat('o', CHUNK), repeat('n', CHUNK));
				var ciphertext = ciphertextPath(fs, file);

				try (var ch = FileChannel.open(file, READ, WRITE)) {
					ch.write(StandardCharsets.UTF_8.encode("x"), 100);
					overwriteInPlace(ciphertext, newer);
					assertThrows(IOException.class, ch::close);
				}

				var event = awaitConflictEvent(events);
				assertEquals("contents.c9r", event.ciphertextPath().getFileName().toString());
				assertEquals(name, event.cleartextPath());
				assertArrayEquals(repeat('n', CHUNK), Files.readAllBytes(file));
			}
		}

		@ParameterizedTest(name = "{0} bytes")
		@ValueSource(ints = {1, CHUNK})
		@DisplayName("A later write with nothing unsaved applies to the new version, even over a chunk a reader cached")
		public void testCleanWriteAppliesToNewVersion(int length) throws IOException {
			try (var fs = setupCryptoFs(50, 100, false, events::add)) {
				var file = fs.getPath("/a.txt");
				var newer = olderOnDiskReturningNewer(fs, file, repeat('o', 3 * CHUNK), repeat('n', 3 * CHUNK));

				try (var reader = FileChannel.open(file, READ); var writer = FileChannel.open(file, READ, WRITE)) {
					reader.read(ByteBuffer.allocate(10), 0);
					overwriteInPlace(ciphertextPath(fs, file), newer);
					writer.write(ByteBuffer.wrap(repeat('x', length)), 0);
				}

				var expected = repeat('n', 3 * CHUNK);
				Arrays.fill(expected, 0, length, (byte) 'x');
				assertArrayEquals(expected, Files.readAllBytes(file));
				assertTrue(events.isEmpty());
			}
		}

		@ParameterizedTest(name = "chunk cached before: {0}")
		@ValueSource(booleans = {false, true})
		@DisplayName("A read past a shrunken end returns the available bytes and then EOF")
		public void testReadPastShrunkenEnd(boolean cachedBefore) throws IOException {
			try (var fs = setupCryptoFs(50, 100, false, events::add)) {
				var file = fs.getPath("/a.txt");
				var newer = olderOnDiskReturningNewer(fs, file, repeat('o', 3 * CHUNK), repeat('n', CHUNK + 100));

				try (var ch = FileChannel.open(file, READ)) {
					if (cachedBefore) {
						ch.read(ByteBuffer.allocate(10), 2L * CHUNK + 5);
					}
					overwriteInPlace(ciphertextPath(fs, file), newer);

					assertTimeoutPreemptively(Duration.ofSeconds(10), () -> {
						assertEquals(-1, ch.read(ByteBuffer.allocate(10), 2L * CHUNK));
						assertEquals(-1, ch.read(ByteBuffer.allocate(10), CHUNK + 500L));
						var straddling = ByteBuffer.allocate(200);
						assertEquals(50, ch.read(straddling, CHUNK + 50L));
						assertArrayEquals(repeat('n', 50), Arrays.copyOf(straddling.array(), 50));
					});
				}

				assertArrayEquals(repeat('n', CHUNK + 100), Files.readAllBytes(file));
			}
		}

		@Test
		@DisplayName("A remainder shorter than a chunk's overhead reads as EOF")
		public void testReadOfRemainderShorterThanOverhead() throws IOException {
			try (var fs = setupCryptoFs(50, 100, false, events::add)) {
				var file = fs.getPath("/a.txt");
				Files.write(file, repeat('o', 3 * CHUNK));
				var ciphertext = ciphertextPath(fs, file);
				var shrunken = Arrays.copyOf(Files.readAllBytes(ciphertext), HEADER_SIZE + CIPHERTEXT_CHUNK + 10);

				try (var ch = FileChannel.open(file, READ)) {
					overwriteInPlace(ciphertext, shrunken);

					assertTimeoutPreemptively(Duration.ofSeconds(10), () -> {
						assertEquals(-1, ch.read(ByteBuffer.allocate(10), CHUNK));
						assertEquals("oooo", read(ch, CHUNK - 4L, 4));
					});
				}

				assertArrayEquals(shrunken, Files.readAllBytes(ciphertext));
				assertArrayEquals(new byte[0], Files.readAllBytes(file)); // a file whose size is invalid at its first open opens as empty
			}
		}

		@ParameterizedTest(name = "dirty chunk {0}")
		@ValueSource(ints = {0, 3})
		@DisplayName("A cached chunk past a shrunken end reads as EOF, also next to a dirty chunk")
		public void testCachedChunkPastShrunkenEndWithDirtyChunk(int dirtyChunk) throws IOException {
			try (var fs = setupCryptoFs(50, 100, false, events::add)) {
				var file = fs.getPath("/a.txt");
				var newer = olderOnDiskReturningNewer(fs, file, repeat('o', 4 * CHUNK), repeat('n', CHUNK));

				try (var ch = FileChannel.open(file, READ, WRITE)) {
					ch.read(ByteBuffer.allocate(10), 2L * CHUNK);
					ch.write(StandardCharsets.UTF_8.encode("x"), dirtyChunk * (long) CHUNK);
					overwriteInPlace(ciphertextPath(fs, file), newer);

					assertTimeoutPreemptively(Duration.ofSeconds(10), () -> assertEquals(-1, ch.read(ByteBuffer.allocate(10), 2L * CHUNK)));
					assertThrows(IOException.class, ch::close);
				}

				assertArrayEquals(repeat('n', CHUNK), Files.readAllBytes(file));
			}
		}

		@Test
		@DisplayName("A truncate that meets a conflict leaves every chunk readable")
		public void testRefusedPartialTruncate() throws IOException {
			try (var fs = setupCryptoFs(50, 100, false, events::add)) {
				var file = fs.getPath("/a.txt");
				var newer = olderOnDiskReturningNewer(fs, file, repeat('o', 3 * CHUNK), repeat('n', 3 * CHUNK));

				try (var ch = FileChannel.open(file, READ, WRITE)) {
					ch.write(StandardCharsets.UTF_8.encode("x"), 2L * CHUNK);
					overwriteInPlace(ciphertextPath(fs, file), newer);
					assertThrows(IOException.class, () -> ch.truncate(CHUNK + 10L));
					assertEquals("n".repeat(20), read(ch, CHUNK, 20)); // reads past the size the refused truncate asked for
					assertThrows(IOException.class, ch::close);
				}

				assertArrayEquals(repeat('n', 3 * CHUNK), Files.readAllBytes(file));
			}
		}

		@Test
		@DisplayName("Truncating to zero through an old channel leaves another header's version alone")
		public void testTruncateToZeroAfterHeaderChange() throws IOException {
			try (var fs = setupCryptoFs(50, 100, false, events::add)) {
				var file = fs.getPath("/a.txt");
				Files.write(file, repeat('o', 2 * CHUNK));
				var other = ciphertextOfOtherFile(fs, repeat('R', 2 * CHUNK));
				var ciphertext = ciphertextPath(fs, file);

				try (var ch = FileChannel.open(file, READ, WRITE)) {
					overwriteInPlace(ciphertext, other);
					assertThrows(IOException.class, () -> ch.truncate(0));
					assertThrows(IOException.class, ch::close);
				}

				assertArrayEquals(other, Files.readAllBytes(ciphertext));
			}
		}

		@Test
		@DisplayName("After a conflict, a new open works on the current ciphertext while the old channel stays open")
		public void testReopenWithHolder() throws IOException {
			try (var fs = setupCryptoFs(50, 100, false, events::add)) {
				var file = fs.getPath("/a.txt");
				var newer = olderOnDiskReturningNewer(fs, file, repeat('o', 2 * CHUNK), repeat('n', 2 * CHUNK));

				try (var holder = FileChannel.open(file, READ, WRITE)) {
					holder.write(StandardCharsets.UTF_8.encode("x"), 5);
					overwriteInPlace(ciphertextPath(fs, file), newer);
					assertThrows(IOException.class, () -> holder.force(false));
					try (var fresh = FileChannel.open(file, READ, WRITE)) {
						assertEquals("nnnn", read(fresh, 0, 4));
						fresh.write(StandardCharsets.UTF_8.encode("y"), 0);
					}
					assertThrows(IOException.class, holder::close);
				}

				var expected = repeat('n', 2 * CHUNK);
				expected[0] = 'y';
				assertArrayEquals(expected, Files.readAllBytes(file));
				awaitConflictEvent(events);
			}
		}

		@ParameterizedTest(name = "new size {0}")
		@ValueSource(ints = {CHUNK + 20, 3 * CHUNK + 20})
		@DisplayName("A relative append uses the current end of the file")
		public void testAppendAfterForeignSizeChange(int newSize) throws IOException {
			try (var fs = setupCryptoFs(50, 100, false, events::add)) {
				var file = fs.getPath("/a.txt");
				var newer = olderOnDiskReturningNewer(fs, file, repeat('o', 2 * CHUNK), repeat('n', newSize));

				try (var ch = FileChannel.open(file, APPEND)) {
					overwriteInPlace(ciphertextPath(fs, file), newer);
					ch.write(StandardCharsets.UTF_8.encode("END"));
				}

				var expected = Arrays.copyOf(repeat('n', newSize), newSize + 3);
				System.arraycopy("END".getBytes(StandardCharsets.UTF_8), 0, expected, newSize, 3);
				assertArrayEquals(expected, Files.readAllBytes(file));
			}
		}

		@ParameterizedTest(name = "new size {0}")
		@ValueSource(ints = {CHUNK + 20, 3 * CHUNK + 20})
		@DisplayName("transferFrom checks its position against the current end of the file")
		public void testTransferFromAfterForeignSizeChange(int newSize) throws IOException {
			try (var fs = setupCryptoFs(50, 100, false, events::add)) {
				var file = fs.getPath("/a.txt");
				var newer = olderOnDiskReturningNewer(fs, file, repeat('o', 2 * CHUNK), repeat('n', newSize));

				try (var ch = FileChannel.open(file, READ, WRITE)) {
					overwriteInPlace(ciphertextPath(fs, file), newer);
					var source = Channels.newChannel(new ByteArrayInputStream("END".getBytes(StandardCharsets.UTF_8)));
					assertEquals(3, ch.transferFrom(source, newSize, 3));
				}

				var expected = Arrays.copyOf(repeat('n', newSize), newSize + 3);
				System.arraycopy("END".getBytes(StandardCharsets.UTF_8), 0, expected, newSize, 3);
				assertArrayEquals(expected, Files.readAllBytes(file));
			}
		}

		@Test
		@DisplayName("A file whose ciphertext size was already invalid when opened stays writable")
		public void testInvalidSizeBeforeOpenStaysWritable() throws IOException {
			try (var fs = setupCryptoFs(50, 100, false, events::add)) {
				var file = fs.getPath("/a.txt");
				Files.write(file, repeat('o', 2 * CHUNK));
				var ciphertext = ciphertextPath(fs, file);
				overwriteInPlace(ciphertext, Arrays.copyOf(Files.readAllBytes(ciphertext), HEADER_SIZE + CIPHERTEXT_CHUNK + 10));

				try (var ch = FileChannel.open(file, READ, WRITE)) {
					ch.write(StandardCharsets.UTF_8.encode("helloworld"), 0);
					ch.truncate(5);
				}

				assertEquals("hello", Files.readString(file));
				assertTrue(events.isEmpty());
			}
		}

		@Test
		@DisplayName("A clean write into a tail another writer is extending fails and leaves its bytes")
		public void testCleanWriteIntoTailBeingExtended() throws IOException {
			try (var fs = setupCryptoFs(50, 100, false, events::add)) {
				var file = fs.getPath("/a.txt");
				Files.write(file, repeat('o', CHUNK + 100));
				var ciphertext = ciphertextPath(fs, file);

				byte[] extended;
				try (var ch = FileChannel.open(file, READ, WRITE)) {
					ch.read(ByteBuffer.allocate(10), CHUNK);
					var original = Files.readAllBytes(ciphertext);
					extended = Arrays.copyOf(original, original.length + 50);
					overwriteInPlace(ciphertext, extended);

					assertThrows(IOException.class, () -> ch.write(StandardCharsets.UTF_8.encode("x"), CHUNK + 5L));
				}

				assertArrayEquals(extended, Files.readAllBytes(ciphertext));
			}
		}

		@Test
		@DisplayName("A write whose eviction finds the conflict fails, and the new version's chunks survive")
		public void testEvictionFindsConflict() throws IOException {
			try (var fs = setupCryptoFs(50, 100, false, events::add)) {
				var file = fs.getPath("/a.txt");
				var newer = olderOnDiskReturningNewer(fs, file, repeat('o', 12 * CHUNK), repeat('n', 12 * CHUNK));
				var writtenChunks = new HashSet<Integer>();
				var lastSuccess = new AtomicReference<Instant>();

				try (var ch = FileChannel.open(file, READ, WRITE)) {
					ch.write(StandardCharsets.UTF_8.encode("x"), 10);
					lastSuccess.set(Instant.now());
					overwriteInPlace(ciphertextPath(fs, file), newer);
					assertThrows(IOException.class, () -> writeUntilEviction(ch, writtenChunks, lastSuccess));
					assertThrows(IOException.class, ch::close);
				}

				var event = awaitConflictEvent(events);
				assertTrue(event.timestamp().isAfter(lastSuccess.get()), "a write succeeded although its eviction found the conflict");
				var stored = Files.readAllBytes(file);
				assertEquals(12 * CHUNK, stored.length);
				for (int chunk = 0; chunk < 12; chunk++) {
					if (!writtenChunks.contains(chunk)) { // including chunk 0, whose save was refused
						assertArrayEquals(repeat('n', CHUNK), Arrays.copyOfRange(stored, chunk * CHUNK, (chunk + 1) * CHUNK), "chunk " + chunk);
					}
				}
			}
		}

		private static void writeUntilEviction(FileChannel ch, Set<Integer> writtenChunks, AtomicReference<Instant> lastSuccess) throws IOException {
			for (int round = 0; round < 20; round++) {
				for (int chunk = 1; chunk < 12; chunk++) {
					var data = chunk % 2 == 0 ? repeat('y', CHUNK) : new byte[]{'y'};
					writtenChunks.add(chunk);
					ch.write(ByteBuffer.wrap(data), chunk * (long) CHUNK);
					lastSuccess.set(Instant.now());
				}
			}
		}

		@Test
		@DisplayName("A cached chunk stays readable after a header conflict, without a decryption event")
		public void testCachedReadAfterHeaderConflict() throws IOException {
			try (var fs = setupCryptoFs(50, 100, false, events::add)) {
				var file = fs.getPath("/a.txt");
				Files.write(file, repeat('o', 2 * CHUNK));
				var other = ciphertextOfOtherFile(fs, repeat('R', 2 * CHUNK));

				try (var ch = FileChannel.open(file, READ, WRITE)) {
					assertEquals("oooo", read(ch, 0, 4));
					overwriteInPlace(ciphertextPath(fs, file), other);
					assertThrows(IOException.class, () -> ch.write(StandardCharsets.UTF_8.encode("x"), 5));
					assertEquals("oooo", read(ch, 0, 4));
					assertThrows(IOException.class, ch::close);
				}

				awaitConflictEvent(events);
				assertTrue(events.stream().noneMatch(DecryptionFailedEvent.class::isInstance));
				assertArrayEquals(repeat('R', 2 * CHUNK), Files.readAllBytes(file));
			}
		}

		@ParameterizedTest(name = "same header: {0}")
		@ValueSource(booleans = {true, false})
		@DisplayName("A refused dirty chunk is served while it is cached")
		public void testRefusedDirtyChunkIsServed(boolean sameHeader) throws IOException {
			try (var fs = setupCryptoFs(50, 100, false, events::add)) {
				var file = fs.getPath("/a.txt");
				var replacement = sameHeader //
						? olderOnDiskReturningNewer(fs, file, repeat('o', 2 * CHUNK), repeat('n', 2 * CHUNK)) //
						: ciphertextOfOtherFileAfterWriting(fs, file);

				try (var ch = FileChannel.open(file, READ, WRITE)) {
					ch.write(StandardCharsets.UTF_8.encode("xxxx"), 0);
					overwriteInPlace(ciphertextPath(fs, file), replacement);
					assertThrows(IOException.class, () -> ch.force(false));
					assertEquals("xxxx", read(ch, 0, 4));
					assertThrows(IOException.class, ch::close);
				}

				assertTrue(events.stream().noneMatch(DecryptionFailedEvent.class::isInstance));
				assertArrayEquals(repeat(sameHeader ? 'n' : 'R', 2 * CHUNK), Files.readAllBytes(file));
			}
		}

		private byte[] ciphertextOfOtherFileAfterWriting(FileSystem fs, Path file) throws IOException {
			Files.write(file, repeat('o', 2 * CHUNK));
			return ciphertextOfOtherFile(fs, repeat('R', 2 * CHUNK));
		}

		@Test
		@DisplayName("Closing a reader during cached reads doesn't break an open writer")
		public void testCloseReaderDuringCachedReads() throws IOException, InterruptedException, ExecutionException, TimeoutException {
			try (var fs = setupCryptoFs(50, 100, false, events::add)) {
				var file = fs.getPath("/a.txt");
				Files.write(file, repeat('o', CHUNK));

				try (var writer = FileChannel.open(file, READ, WRITE)) {
					assertEquals("oooo", read(writer, 0, 4)); // caches the chunk, so that the reads below never load through a closing channel
					for (int i = 0; i < 200; i++) {
						var reader = FileChannel.open(file, READ);
						var close = new FutureTask<Void>(() -> {
							reader.close();
							return null;
						});
						Thread.ofVirtual().start(close);
						assertEquals("oooo", read(writer, 0, 4));
						close.get(10, TimeUnit.SECONDS); // rethrows a failure of the close
					}
					writer.write(StandardCharsets.UTF_8.encode("x"), 0);
				}

				var expected = repeat('o', CHUNK);
				expected[0] = 'x';
				assertArrayEquals(expected, Files.readAllBytes(file));
			}
		}

		@Test
		@DisplayName("A valid write after a rejected negative position can still adopt a changed size")
		public void testWriteAfterNegativePosition() throws IOException {
			try (var fs = setupCryptoFs(50, 100, false, events::add)) {
				var file = fs.getPath("/a.txt");
				var newer = olderOnDiskReturningNewer(fs, file, repeat('o', 2 * CHUNK), repeat('n', 3 * CHUNK));

				try (var ch = FileChannel.open(file, READ, WRITE)) {
					var buf = StandardCharsets.UTF_8.encode("x");
					assertThrows(IllegalArgumentException.class, () -> ch.write(buf, -1));
					overwriteInPlace(ciphertextPath(fs, file), newer);
					ch.write(StandardCharsets.UTF_8.encode("y"), 3L * CHUNK);
				}

				var expected = Arrays.copyOf(repeat('n', 3 * CHUNK), 3 * CHUNK + 1);
				expected[3 * CHUNK] = 'y';
				assertArrayEquals(expected, Files.readAllBytes(file));
			}
		}

		@ParameterizedTest(name = "moved before: {0}")
		@ValueSource(booleans = {false, true})
		@DisplayName("A decryption event after a detach names the file, also after a move")
		public void testDecryptionEventAfterDetach(boolean moved) throws IOException {
			try (var fs = setupCryptoFs(50, 100, false, events::add)) {
				var file = fs.getPath("/a.txt");
				var target = moved ? fs.getPath("/b.txt") : file;
				Files.write(file, repeat('o', 2 * CHUNK));
				var other = ciphertextOfOtherFile(fs, repeat('R', 2 * CHUNK));
				Path ciphertext;

				try (var holder = FileChannel.open(file, READ, WRITE)) {
					holder.write(StandardCharsets.UTF_8.encode("x"), 0);
					if (moved) {
						Files.move(file, target);
					}
					ciphertext = ciphertextPath(fs, target);
					overwriteInPlace(ciphertext, other);
					assertThrows(IOException.class, () -> holder.force(false));
					try (var _ = FileChannel.open(target, READ)) { // detaches the holder's open file
						assertThrows(IOException.class, () -> holder.read(ByteBuffer.allocate(4), CHUNK));
					}
					assertThrows(IOException.class, holder::close);
				}

				await().atMost(Duration.ofSeconds(5)).until(() -> events.stream().anyMatch(DecryptionFailedEvent.class::isInstance));
				var event = events.stream().filter(DecryptionFailedEvent.class::isInstance).map(DecryptionFailedEvent.class::cast).findFirst().orElseThrow();
				assertEquals(ciphertext, event.ciphertextPath());
				assertArrayEquals(repeat('R', 2 * CHUNK), Files.readAllBytes(target));
			}
		}

		@Test
		@DisplayName("A decryption event handler forcing the same file during a failed reload doesn't hang")
		public void testDecryptionHandlerForcingSameFile() throws IOException, InterruptedException {
			var writerRef = new AtomicReference<FileChannel>();
			var handled = new CountDownLatch(1);
			Consumer<FilesystemEvent> forcingHandler = event -> {
				if (event instanceof DecryptionFailedEvent && handled.getCount() > 0) { // the failed reload's event, not those of the reopen below
					assertDoesNotThrow(() -> writerRef.get().force(false));
					handled.countDown();
				}
			};
			try (var fs = setupCryptoFs(50, 100, false, forcingHandler)) {
				var file = fs.getPath("/a.txt");
				Files.write(file, repeat('o', CHUNK));
				var ciphertext = ciphertextPath(fs, file);
				var corrupted = Files.readAllBytes(ciphertext);
				corrupted[HEADER_SIZE] ^= 1;

				try (var writer = FileChannel.open(file, READ, WRITE)) {
					writerRef.set(writer);
					writer.read(ByteBuffer.allocate(4), 0);
					overwriteInPlace(ciphertext, corrupted);

					assertTimeoutPreemptively(Duration.ofSeconds(10), () -> {
						assertThrows(IOException.class, () -> writer.write(StandardCharsets.UTF_8.encode("x"), 5));
					});
					assertTrue(handled.await(10, TimeUnit.SECONDS));
				}

				assertArrayEquals(corrupted, Files.readAllBytes(ciphertext));
				assertThrows(IOException.class, () -> Files.readAllBytes(file)); // the damaged chunk was left as it is
			}
		}

		@ParameterizedTest(name = "full chunk: {0}")
		@ValueSource(booleans = {false, true})
		@DisplayName("An unsaved write keeps a later write from adopting a size another process changed")
		public void testUnsavedWriteBlocksForeignSize(boolean fullChunk) throws IOException {
			try (var fs = setupCryptoFs(50, 100, false, events::add)) {
				var file = fs.getPath("/a.txt");
				Files.write(file, repeat('o', 2 * CHUNK));
				var ciphertext = ciphertextPath(fs, file);
				var original = Files.readAllBytes(ciphertext);
				var grown = Arrays.copyOf(original, original.length + 100); // leaves the chunk the write edits as it is

				try (var ch = FileChannel.open(file, READ, WRITE)) {
					ch.write(ByteBuffer.wrap(repeat('x', fullChunk ? CHUNK : 1)), 0);
					overwriteInPlace(ciphertext, grown);
					assertThrows(IOException.class, () -> ch.write(StandardCharsets.UTF_8.encode("z"), CHUNK + 5L));
					assertThrows(IOException.class, ch::close);
				}

				awaitConflictEvent(events);
				assertArrayEquals(grown, Files.readAllBytes(ciphertext));
			}
		}

		@Test
		@DisplayName("A truncate after another process changed the size applies to the new version")
		public void testTruncateAfterForeignSizeChange() throws IOException {
			try (var fs = setupCryptoFs(50, 100, false, events::add)) {
				var file = fs.getPath("/a.txt");
				var newer = olderOnDiskReturningNewer(fs, file, repeat('o', 2 * CHUNK), repeat('n', 3 * CHUNK));

				try (var ch = FileChannel.open(file, READ, WRITE)) {
					overwriteInPlace(ciphertextPath(fs, file), newer);
					ch.truncate(CHUNK + 10L);
				}

				assertArrayEquals(repeat('n', CHUNK + 10), Files.readAllBytes(file));
				assertTrue(events.isEmpty());
			}
		}

		@Test
		@DisplayName("An append after another process grew the file doesn't serve a shorter tail chunk cached before")
		public void testAppendAfterForeignGrowthOverCachedTail() throws IOException {
			try (var fs = setupCryptoFs(50, 100, false, events::add)) {
				var file = fs.getPath("/a.txt");
				var newer = olderOnDiskReturningNewer(fs, file, repeat('o', CHUNK + 100), repeat('n', 3 * CHUNK));
				var expected = Arrays.copyOf(repeat('n', 3 * CHUNK), 3 * CHUNK + 3);
				System.arraycopy("END".getBytes(StandardCharsets.UTF_8), 0, expected, 3 * CHUNK, 3);

				try (var reader = FileChannel.open(file, READ); var writer = FileChannel.open(file, APPEND)) {
					reader.read(ByteBuffer.allocate(10), CHUNK);
					overwriteInPlace(ciphertextPath(fs, file), newer);
					writer.write(StandardCharsets.UTF_8.encode("END"));

					assertArrayEquals(expected, Files.readAllBytes(file)); // through the same open file
				}

				assertArrayEquals(expected, Files.readAllBytes(file));
				assertTrue(events.isEmpty());
			}
		}

		@Test
		@DisplayName("A write past an end another process truncated to a chunk boundary is refused")
		public void testWritePastForeignShrink() throws IOException {
			try (var fs = setupCryptoFs(50, 100, false, events::add)) {
				var file = fs.getPath("/a.txt");
				Files.write(file, repeat('o', 3 * CHUNK));
				var ciphertext = ciphertextPath(fs, file);
				var truncated = Arrays.copyOf(Files.readAllBytes(ciphertext), HEADER_SIZE + CIPHERTEXT_CHUNK);

				try (var ch = FileChannel.open(file, READ, WRITE)) {
					overwriteInPlace(ciphertext, truncated);
					assertThrows(IOException.class, () -> ch.write(StandardCharsets.UTF_8.encode("x"), 2L * CHUNK + 5));
					assertThrows(IOException.class, ch::close);
				}

				awaitConflictEvent(events);
				assertArrayEquals(repeat('o', CHUNK), Files.readAllBytes(file));
			}
		}

		@Test
		@DisplayName("After another channel adopted a shrink, a write past the new end is refused too")
		public void testWritePastForeignShrinkAdoptedByOtherChannel() throws IOException {
			try (var fs = setupCryptoFs(50, 100, false, events::add)) {
				var file = fs.getPath("/a.txt");
				Files.write(file, repeat('o', 3 * CHUNK));
				var ciphertext = ciphertextPath(fs, file);
				var truncated = Arrays.copyOf(Files.readAllBytes(ciphertext), HEADER_SIZE + CIPHERTEXT_CHUNK);

				try (var stale = FileChannel.open(file, READ, WRITE); var other = FileChannel.open(file, READ, WRITE)) {
					overwriteInPlace(ciphertext, truncated);
					other.write(StandardCharsets.UTF_8.encode("y"), 5); // adopts the new size
					other.force(false);
					assertThrows(IOException.class, () -> stale.write(StandardCharsets.UTF_8.encode("x"), 2L * CHUNK + 5));
					assertThrows(IOException.class, other::close); // the conflict is the open file's, so every channel's close reports it
					assertThrows(IOException.class, stale::close);
				}

				awaitConflictEvent(events);
				var expected = repeat('o', CHUNK);
				expected[5] = 'y';
				assertArrayEquals(expected, Files.readAllBytes(file));
			}
		}

		@Test
		@DisplayName("A write past an end another process grew is no gap over removed data and succeeds")
		public void testWritePastForeignGrowth() throws IOException {
			try (var fs = setupCryptoFs(50, 100, false, events::add)) {
				var file = fs.getPath("/a.txt");
				var newer = olderOnDiskReturningNewer(fs, file, repeat('o', CHUNK), repeat('n', 2 * CHUNK));

				try (var ch = FileChannel.open(file, READ, WRITE)) {
					overwriteInPlace(ciphertextPath(fs, file), newer);
					ch.write(StandardCharsets.UTF_8.encode("x"), 3L * CHUNK + 5);
				}

				var expected = Arrays.copyOf(repeat('n', 2 * CHUNK), 3 * CHUNK + 6);
				expected[3 * CHUNK + 5] = 'x';
				assertArrayEquals(expected, Files.readAllBytes(file));
				assertTrue(events.isEmpty());
			}
		}

		@Test
		@DisplayName("After an adopted shrink, a write past the end stays refused once another process grew the file again")
		public void testWritePastForeignRegrowthAfterShrink() throws IOException {
			try (var fs = setupCryptoFs(50, 100, false, events::add)) {
				var file = fs.getPath("/a.txt");
				Files.write(file, repeat('o', 3 * CHUNK));
				var ciphertext = ciphertextPath(fs, file);
				var original = Files.readAllBytes(ciphertext);
				var truncated = Arrays.copyOf(original, HEADER_SIZE + CIPHERTEXT_CHUNK);

				try (var ch = FileChannel.open(file, READ, WRITE)) {
					overwriteInPlace(ciphertext, truncated);
					ch.write(StandardCharsets.UTF_8.encode("y"), 5); // adopts the shrink
					ch.force(false);
					var saved = Files.readAllBytes(ciphertext);
					var regrown = Arrays.copyOf(saved, original.length); // the removed chunks come back
					System.arraycopy(original, saved.length, regrown, saved.length, original.length - saved.length);
					overwriteInPlace(ciphertext, regrown);
					assertThrows(IOException.class, () -> ch.write(StandardCharsets.UTF_8.encode("x"), 4L * CHUNK + 5));
					assertThrows(IOException.class, ch::close);
				}

				awaitConflictEvent(events);
				var expected = repeat('o', 3 * CHUNK);
				expected[5] = 'y';
				assertArrayEquals(expected, Files.readAllBytes(file));
			}
		}

	}

	private static FileWriteConflictEvent awaitConflictEvent(List<FilesystemEvent> events) {
		await().atMost(Duration.ofSeconds(5)).until(() -> events.stream().anyMatch(FileWriteConflictEvent.class::isInstance));
		var conflicts = events.stream().filter(FileWriteConflictEvent.class::isInstance).map(FileWriteConflictEvent.class::cast).toList();
		assertEquals(1, conflicts.size());
		return conflicts.getFirst();
	}

	// leaves the older version on disk and returns the newer one's ciphertext, which has the same header
	private static byte[] olderOnDiskReturningNewer(FileSystem fs, Path file, byte[] olderContent, byte[] newerContent) throws IOException {
		Files.write(file, olderContent);
		var ciphertext = ciphertextPath(fs, file);
		var olderCiphertext = Files.readAllBytes(ciphertext);
		Files.write(file, newerContent);
		var newerCiphertext = Files.readAllBytes(ciphertext);
		overwriteInPlace(ciphertext, olderCiphertext);
		return newerCiphertext;
	}

	private static byte[] ciphertextOfOtherFile(FileSystem fs, byte[] content) throws IOException {
		var other = fs.getPath("/other.txt");
		Files.write(other, content);
		var ciphertext = Files.readAllBytes(ciphertextPath(fs, other));
		Files.delete(other);
		return ciphertext;
	}

	// changes the ciphertext like another process writing to the same file does, keeping its identity
	private static void overwriteInPlace(Path ciphertext, byte[] content) throws IOException {
		try (var raw = FileChannel.open(ciphertext, WRITE)) {
			var buf = ByteBuffer.wrap(content);
			while (buf.hasRemaining()) {
				raw.write(buf, buf.position());
			}
			raw.truncate(content.length);
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
