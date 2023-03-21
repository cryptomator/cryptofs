/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptofs;

import com.google.common.jimfs.Configuration;
import com.google.common.jimfs.Jimfs;
import org.cryptomator.cryptofs.util.ByteBuffers;
import org.cryptomator.cryptolib.api.Masterkey;
import org.cryptomator.cryptolib.api.MasterkeyLoader;
import org.cryptomator.cryptolib.api.MasterkeyLoadingFailedException;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.condition.EnabledOnOs;
import org.junit.jupiter.api.condition.OS;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mockito;

import java.io.IOException;
import java.lang.invoke.MethodHandles;
import java.net.URI;
import java.nio.ByteBuffer;
import java.nio.channels.Channels;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileSystem;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.FileTime;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.List;
import java.util.Random;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.stream.IntStream;
import java.util.stream.Stream;

import static java.lang.Math.min;
import static java.lang.String.format;
import static java.nio.file.StandardOpenOption.APPEND;
import static java.nio.file.StandardOpenOption.CREATE;
import static java.nio.file.StandardOpenOption.CREATE_NEW;
import static java.nio.file.StandardOpenOption.READ;
import static java.nio.file.StandardOpenOption.TRUNCATE_EXISTING;
import static java.nio.file.StandardOpenOption.WRITE;
import static org.cryptomator.cryptofs.CryptoFileSystemProperties.cryptoFileSystemProperties;
import static org.cryptomator.cryptofs.util.ByteBuffers.repeat;

public class CryptoFileChannelWriteReadIntegrationTest {

	private static final int EOF = -1;

	@Nested
	@TestInstance(TestInstance.Lifecycle.PER_CLASS)
	@EnabledOnOs(OS.WINDOWS)
	public class Windows {

		private FileSystem fileSystem;

		@BeforeAll
		public void setupClass(@TempDir Path tmpDir) throws IOException, MasterkeyLoadingFailedException {
			MasterkeyLoader keyLoader = Mockito.mock(MasterkeyLoader.class);
			Mockito.when(keyLoader.loadKey(Mockito.any())).thenAnswer(ignored -> new Masterkey(new byte[64]));
			CryptoFileSystemProperties properties = cryptoFileSystemProperties().withKeyLoader(keyLoader).build();
			CryptoFileSystemProvider.initialize(tmpDir, properties, URI.create("test:key"));
			fileSystem = CryptoFileSystemProvider.newFileSystem(tmpDir, properties);
		}

		// tests https://github.com/cryptomator/cryptofs/issues/69
		@Test
		public void testCloseDoesNotBumpModifiedDate() throws IOException {
			Path file = fileSystem.getPath("/file.txt");

			Instant t0, t1;
			t0 = Instant.ofEpochSecond(123456789).truncatedTo(ChronoUnit.SECONDS);

			try (FileChannel ch = FileChannel.open(file, CREATE_NEW, WRITE)) {
				Files.setLastModifiedTime(file, FileTime.from(t0));
			}

			t1 = Files.getLastModifiedTime(file).toInstant().truncatedTo(ChronoUnit.SECONDS);
			Assertions.assertEquals(t0, t1);
		}

		@Test
		public void testLastModifiedIsPreservedOverSeveralOperations() throws IOException, InterruptedException {
			Path file = fileSystem.getPath("/file2.txt");

			Instant t0, t1, t2, t3, t4, t5;
			t0 = Instant.ofEpochSecond(123456789).truncatedTo(ChronoUnit.SECONDS);
			ByteBuffer data = ByteBuffer.wrap("CryptoFS".getBytes());

			try (FileChannel ch = FileChannel.open(file, CREATE_NEW, WRITE)) {
				t1 = Files.getLastModifiedTime(file).toInstant().truncatedTo(ChronoUnit.MILLIS);
				Thread.sleep(50);

				ch.write(data);
				ch.force(true);
				Thread.sleep(50);
				t2 = Files.getLastModifiedTime(file).toInstant().truncatedTo(ChronoUnit.MILLIS);

				Files.setLastModifiedTime(file, FileTime.from(t0));
				ch.force(true);
				Thread.sleep(50);
				t3 = Files.getLastModifiedTime(file).toInstant().truncatedTo(ChronoUnit.MILLIS);

				ch.write(data);
				ch.force(true);
				Thread.sleep(1000);
				t4 = Files.getLastModifiedTime(file).toInstant().truncatedTo(ChronoUnit.SECONDS);

			}

			t5 = Files.getLastModifiedTime(file).toInstant().truncatedTo(ChronoUnit.SECONDS);
			Assertions.assertNotEquals(t1, t2);
			Assertions.assertEquals(t0, t3);
			Assertions.assertNotEquals(t4, t3);
			Assertions.assertEquals(t4, t5);
		}

	}

	@Nested
	@TestInstance(TestInstance.Lifecycle.PER_CLASS)
	public class PlatformIndependent {

		private FileSystem inMemoryFs;
		private FileSystem fileSystem;

		private Path file;

		@BeforeAll
		public void beforeAll() throws IOException, MasterkeyLoadingFailedException {
			inMemoryFs = Jimfs.newFileSystem();
			Path vaultPath = inMemoryFs.getPath("vault");
			Files.createDirectories(vaultPath);
			MasterkeyLoader keyLoader = Mockito.mock(MasterkeyLoader.class);
			Mockito.when(keyLoader.loadKey(Mockito.any())).thenAnswer(ignored -> new Masterkey(new byte[64]));
			var properties = cryptoFileSystemProperties().withKeyLoader(keyLoader).build();
			CryptoFileSystemProvider.initialize(vaultPath, properties, URI.create("test:key"));
			fileSystem = CryptoFileSystemProvider.newFileSystem(vaultPath, properties);
			file = fileSystem.getPath("/test.txt");
		}

		@AfterAll
		public void afterAll() throws IOException {
			fileSystem.close();
			inMemoryFs.close();
		}

		@AfterEach
		public void afterEach() throws IOException {
			Files.deleteIfExists(file);
		}

		@Test
		public void testLockEmptyChannel() throws IOException {
			try (FileChannel ch = FileChannel.open(file, CREATE, WRITE)) {
				try (FileLock lock = ch.lock()) {
					Assertions.assertNotNull(lock);
				}
			}
		}

		@Test
		public void testTryLockEmptyChannel() throws IOException {
			try (FileChannel ch = FileChannel.open(file, CREATE, WRITE)) {
				try (FileLock lock = ch.tryLock()) {
					Assertions.assertNotNull(lock);
				}
			}
		}

		// tests https://github.com/cryptomator/cryptofs/issues/55
		@Test
		public void testCreateNewFileSetsLastModifiedToNow() throws IOException {
			Instant t0, t1, t2;
			t0 = Instant.now().truncatedTo(ChronoUnit.SECONDS);

			try (FileChannel ch = FileChannel.open(file, CREATE, WRITE)) {
				t1 = Files.getLastModifiedTime(file).toInstant().truncatedTo(ChronoUnit.SECONDS);
				Assertions.assertFalse(t1.isBefore(t0));
			}

			t2 = Files.getLastModifiedTime(file).toInstant().truncatedTo(ChronoUnit.SECONDS);
			Assertions.assertFalse(t2.isBefore(t1));
		}

		// tests https://github.com/cryptomator/cryptofs/issues/50
		@Test
		public void testReadWhileStillWriting() throws IOException {
			try (FileChannel ch1 = FileChannel.open(file, CREATE_NEW, WRITE)) {
				// it actually matters that the channel writes more than one chunk size (32k)
				ch1.write(repeat(1).times(35000).asByteBuffer(), 0);
				try (FileChannel ch2 = FileChannel.open(file, READ)) {
					ch1.write(repeat(2).times(5000).asByteBuffer(), 35000);
				}
			}

			try (FileChannel ch1 = FileChannel.open(file, READ)) {
				ByteBuffer buffer = ByteBuffer.allocate(40000);
				int result = ch1.read(buffer);
				Assertions.assertEquals(40000, result);
				Assertions.assertEquals(EOF, ch1.read(ByteBuffer.allocate(0)));
				buffer.flip();
				for (int i = 0; i < 40000; i++) {
					if (i < 35000) {
						Assertions.assertEquals(1, buffer.get(i), format("byte(%d) = 1", i));
					} else {
						Assertions.assertEquals(2, buffer.get(i), format("byte(%d) = 2", i));
					}
				}
			}
		}

		// tests https://github.com/cryptomator/cryptofs/issues/48
		@Test
		public void testTruncateExistingWhileStillOpen() throws IOException {
			try (FileChannel ch1 = FileChannel.open(file, CREATE_NEW, WRITE)) {
				ch1.write(StandardCharsets.UTF_8.encode("goodbye world"), 0);
				ch1.force(true); // will generate a file header
				try (FileChannel ch2 = FileChannel.open(file, CREATE, WRITE, TRUNCATE_EXISTING)) { // reuse existing file header, but will not re-write it
					ch2.write(StandardCharsets.UTF_8.encode("hello world"), 0);
				}
			}

			try (FileChannel ch1 = FileChannel.open(file, READ)) {
				ByteBuffer buf = ByteBuffer.allocate((int) ch1.size());
				ch1.read(buf);
				Assertions.assertArrayEquals("hello world".getBytes(), buf.array());
			}
		}

		// tests https://github.com/cryptomator/cryptofs/issues/22
		@Test
		public void testFileSizeIsZeroAfterCreatingFileChannel() throws IOException {
			try (FileChannel channel = FileChannel.open(file, CREATE, WRITE)) {
				Assertions.assertEquals(0, channel.size());
				Assertions.assertEquals(0, Files.size(file));
			}

			Assertions.assertEquals(0, Files.size(file));
		}

		// tests https://github.com/cryptomator/cryptofs/issues/26
		@Test
		public void testFileSizeIsTenAfterWritingTenBytes() throws IOException {
			try (FileChannel channel = FileChannel.open(file, CREATE, WRITE)) {
				channel.write(ByteBuffer.wrap(new byte[10]));
				Assertions.assertEquals(10, channel.size());
				Assertions.assertEquals(10, Files.size(file));
			}

			Assertions.assertEquals(10, Files.size(file));
		}


		// tests https://github.com/cryptomator/cryptofs/issues/129
		@ParameterizedTest
		@MethodSource
		public void testSkipBeyondEofAndWrite(List<SparseContent> contentRanges) throws IOException {
			// write sparse file
			try (var ch = FileChannel.open(file, CREATE, WRITE)) {
				for (var range : contentRanges) {
					var buf = ByteBuffers.repeat(range.pattern).times(range.len).asByteBuffer();
					ch.write(buf, range.pos);
				}
			}

			// read and compare to expected
			try (var ch = FileChannel.open(file, READ); var in = Channels.newInputStream(ch)) {
				int pos = 0;
				for (var range : contentRanges) {
					// verify gaps are zeroes:
					for (int p = pos; p < range.pos; p++) {
						if (in.read() != 0) {
							Assertions.fail("Expected NIL byte at pos " + p);
						}
					}
					// verify expected values
					for (int p = 0; p < range.len; p++) {
						if (in.read() != range.pattern) {
							Assertions.fail("Expected byte at pos " + (pos + p) + " to be " + range.pattern);
						}
					}
					pos = range.pos + range.len;
				}
			}
		}

		private record SparseContent(byte pattern, int pos, int len) {

		}

		public Stream<List<SparseContent>> testSkipBeyondEofAndWrite() {
			return Stream.of( //
					List.of(new SparseContent((byte) 0x01, 50, 100)), //
					List.of(new SparseContent((byte) 0x01, 0, 1000), new SparseContent((byte) 0x02, 20_000, 1000)), //
					List.of(new SparseContent((byte) 0x01, 0, 1000), new SparseContent((byte) 0x02, 36_000, 1000)), //
					List.of(new SparseContent((byte) 0x01, 2_000_000, 84_000), new SparseContent((byte) 0x02, 3_000_000, 10_000)), //
					List.of(new SparseContent((byte) 0x01, 50, 100), new SparseContent((byte) 0x02, 250, 100), new SparseContent((byte) 0x03, 450, 100), new SparseContent((byte) 0x04, 20_000, 1000), new SparseContent((byte) 0x05, 3_000_000, 10_000)) //
			);
		}

		@Test
		public void testWriteAndReadNothing() throws IOException {
			try (FileChannel channel = FileChannel.open(file, CREATE, WRITE)) {
				channel.write(ByteBuffer.allocate(0));
			}

			try (FileChannel channel = FileChannel.open(file, READ)) {
				Assertions.assertEquals(EOF, channel.read(ByteBuffer.allocate(0)));
			}
		}

		@ParameterizedTest(name = "write {0} bytes and truncate to {1}")
		@CsvSource({"0, 0", "0, 5000", "0, 32768", "0, 40000", "70000, 0", "70000, 30000", "70000, 40000", "70000, 65536", "70000, 80000"})
		public void testWriteDataAndTruncateToOffset(int cleartextSize, int truncateToSize) throws IOException {
			int targetSize = min(truncateToSize, cleartextSize);

			try (FileChannel channel = FileChannel.open(file, CREATE, WRITE)) {
				Assertions.assertEquals(0, channel.size());
				channel.write(repeat(1).times(cleartextSize).asByteBuffer());
				Assertions.assertEquals(cleartextSize, channel.size());
			}

			try (FileChannel channel = FileChannel.open(file, CREATE, WRITE)) {
				Assertions.assertEquals(cleartextSize, channel.size());
				channel.truncate(truncateToSize);
				Assertions.assertEquals(targetSize, channel.size());
			}

			try (FileChannel channel = FileChannel.open(file, READ)) {
				if (targetSize > 0) {
					ByteBuffer buffer = ByteBuffer.allocate(targetSize);
					int result = channel.read(buffer);
					Assertions.assertEquals(targetSize, result);
					buffer.flip();
					for (int i = 0; i < targetSize; i++) {
						Assertions.assertEquals(1, buffer.get(i), format("byte(%d) = 1", i));
					}
				}
				Assertions.assertEquals(EOF, channel.read(ByteBuffer.allocate(0)));
			}
		}

		@ParameterizedTest(name = "write {0} bytes beginning at {1}")
		@CsvSource({"0, 5000", "0, 32768", "0, 40000", "70000, 0", "70000, 40000", "70000, 65536", "70000, 80000"})
		public void testWithWritingOffset(int dataSize, int writeOffset) throws IOException {
			int cleartextSize = dataSize + writeOffset;

			try (FileChannel channel = FileChannel.open(file, CREATE, WRITE)) {
				Assertions.assertEquals(0, channel.size());
				channel.write(repeat(1).times(writeOffset).asByteBuffer());
				Assertions.assertEquals(writeOffset, channel.size());
				channel.write(repeat(2).times(dataSize).asByteBuffer());
				Assertions.assertEquals(cleartextSize, channel.size());
			}

			try (FileChannel channel = FileChannel.open(file, READ)) {
				ByteBuffer buffer = ByteBuffer.allocate(cleartextSize);
				int result = channel.read(buffer);
				Assertions.assertEquals(cleartextSize, result);
				Assertions.assertEquals(EOF, channel.read(ByteBuffer.allocate(0)));
				buffer.flip();
				for (int i = 0; i < cleartextSize; i++) {
					if (i < writeOffset) {
						Assertions.assertEquals(1, buffer.get(i), format("byte(%d) = 1", i));
					} else {
						Assertions.assertEquals(2, buffer.get(i), format("byte(%d) = 2", i));
					}
				}
			}
		}

		@ParameterizedTest(name = "write {0} bytes beginning at {1}")
		@CsvSource({"0, 5000", "0, 32768", "0, 40000", "70000, 0", "70000, 40000", "70000, 65536", "70000, 80000"})
		public void testWithWritingInReverseOrderUsingPositions(int dataSize, int writeOffset) throws IOException {
			int cleartextSize = dataSize + writeOffset;

			try (FileChannel channel = FileChannel.open(file, CREATE, WRITE)) {
				Assertions.assertEquals(0, channel.size());
				channel.write(repeat(2).times(dataSize).asByteBuffer(), writeOffset);
				Assertions.assertEquals(cleartextSize, channel.size());
				channel.write(repeat(1).times(writeOffset).asByteBuffer(), 0);
				Assertions.assertEquals(cleartextSize, channel.size());
			}

			try (FileChannel channel = FileChannel.open(file, READ)) {
				ByteBuffer buffer = ByteBuffer.allocate(cleartextSize);
				int result = channel.read(buffer);
				Assertions.assertEquals(cleartextSize, result);
				Assertions.assertEquals(EOF, channel.read(ByteBuffer.allocate(0)));
				buffer.flip();
				for (int i = 0; i < cleartextSize; i++) {
					if (i < writeOffset) {
						Assertions.assertEquals(1, buffer.get(i), format("byte(%d) = 1", i));
					} else {
						Assertions.assertEquals(2, buffer.get(i), format("byte(%d) = 2", i));
					}
				}
			}
		}

		@ParameterizedTest(name = "write {0} bytes beginngin at {1}")
		@CsvSource({"10000, 32767", "10000, 32768", "10000, 32769", "70000, 65535", "70000, 65536", "70000, 65537"})
		public void testWithSkippingOffset(int dataSize, int writeOffset) throws IOException {
			int cleartextSize = dataSize + writeOffset;

			try (FileChannel channel = FileChannel.open(file, CREATE, WRITE)) {
				Assertions.assertEquals(0, channel.size());
				channel.position(writeOffset);
				channel.write(repeat(2).times(dataSize).asByteBuffer());
				Assertions.assertEquals(cleartextSize, channel.size());
			}

			Assertions.assertEquals(cleartextSize, Files.size(file));

			try (FileChannel channel = FileChannel.open(file, READ)) {
				Assertions.assertEquals(cleartextSize, channel.size());
				ByteBuffer buffer = ByteBuffer.allocate(cleartextSize);
				int result = channel.read(buffer);
				Assertions.assertEquals(cleartextSize, result);
				Assertions.assertEquals(EOF, channel.read(ByteBuffer.allocate(0)));
				buffer.flip();
				for (int i = writeOffset; i < cleartextSize; i++) {
					Assertions.assertEquals(2, buffer.get(i), format("byte(%d) = 2", i));
				}
			}
		}

		@ParameterizedTest(name = "append {0} bytes")
		@ValueSource(ints = {372, 32768, 72389})
		public void testAppend(int dataSize) throws IOException {
			try (FileChannel channel = FileChannel.open(file, CREATE, WRITE, APPEND)) {
				Assertions.assertEquals(0, channel.size());
				channel.write(repeat(1).times(dataSize).asByteBuffer());
				Assertions.assertEquals(dataSize, channel.size());
			}

			try (FileChannel channel = FileChannel.open(file, CREATE, WRITE, APPEND)) {
				Assertions.assertEquals(dataSize, channel.size());
				channel.write(repeat(1).times(dataSize).asByteBuffer());
				channel.write(repeat(1).times(dataSize).asByteBuffer());
				Assertions.assertEquals(3 * dataSize, channel.size());
			}

			try (FileChannel channel = FileChannel.open(file, READ)) {
				ByteBuffer buffer = ByteBuffer.allocate(3 * dataSize);
				int result = channel.read(buffer);
				Assertions.assertEquals(3 * dataSize, result);
				Assertions.assertEquals(EOF, channel.read(ByteBuffer.allocate(0)));
			}
		}

		@RepeatedTest(100)
		public void testConcurrentRead() throws IOException, InterruptedException {
			// prepare test data:
			var content = new byte[10_000_000];
			for (int i = 0; i < 100_000; i++) {
				byte b = (byte) (i % 255);
				Arrays.fill(content, i * 100, (i + 1) * 100, b);
			}

			try (var ch = FileChannel.open(file, CREATE, WRITE, TRUNCATE_EXISTING)) {
				ch.write(ByteBuffer.wrap(content));
			}

			// read concurrently from same file channel:
			var numThreads = 100;
			var rnd = new Random(42L);
			var results = new int[numThreads];
			var resultsHandle = MethodHandles.arrayElementVarHandle(int[].class);
			Arrays.fill(results, 42);
			var executor = Executors.newCachedThreadPool();
			try (var ch = FileChannel.open(file, READ)) {
				for (int i = 0; i < numThreads; i++) {
					int t = i;
					int num = rnd.nextInt(50_000);
					int pos = rnd.nextInt(400_000);
					executor.submit(() -> {
						ByteBuffer buf = ByteBuffer.allocate(num);
						try {
							int read = ch.read(buf, pos);
							if (read != num) {
								System.out.println("thread " + t + " read " + pos + " - " + (pos + num));
								resultsHandle.setOpaque(results, t, -1); // ERROR invalid number of bytes
							} else if (Arrays.equals(content, pos, pos + num, buf.array(), 0, read)) {
								resultsHandle.setOpaque(results, t, 0); // SUCCESS
							} else {
								System.out.println("thread " + t + " read " + pos + " - " + (pos + num));
								resultsHandle.setOpaque(results, t, -2); // ERROR invalid content
							}
						} catch (IOException e) {
							e.printStackTrace();
							resultsHandle.setOpaque(results, t, -3); // ERROR I/O error
						}
					});
				}
				executor.shutdown();
				boolean allTasksFinished = executor.awaitTermination(10, TimeUnit.SECONDS);
				Assertions.assertTrue(allTasksFinished);
			}

			Assertions.assertAll(IntStream.range(0, numThreads).mapToObj(t -> {
				return () -> Assertions.assertEquals(0, resultsHandle.getOpaque(results, t), "thread " + t + " unsuccessful");
			}));
		}

	}

}
