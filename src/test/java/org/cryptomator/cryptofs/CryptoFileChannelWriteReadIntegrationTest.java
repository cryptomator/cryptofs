/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptofs;

import com.google.common.jimfs.Jimfs;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.condition.EnabledOnOs;
import org.junit.jupiter.api.condition.OS;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileSystem;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.FileTime;
import java.time.Instant;
import java.time.temporal.ChronoUnit;

import static java.lang.Math.min;
import static java.lang.String.format;
import static java.nio.file.StandardOpenOption.APPEND;
import static java.nio.file.StandardOpenOption.CREATE;
import static java.nio.file.StandardOpenOption.CREATE_NEW;
import static java.nio.file.StandardOpenOption.READ;
import static java.nio.file.StandardOpenOption.TRUNCATE_EXISTING;
import static java.nio.file.StandardOpenOption.WRITE;
import static org.cryptomator.cryptofs.CryptoFileSystemProperties.cryptoFileSystemProperties;
import static org.cryptomator.cryptofs.CryptoFileSystemUri.create;
import static org.cryptomator.cryptofs.util.ByteBuffers.repeat;

public class CryptoFileChannelWriteReadIntegrationTest {

	private static final int EOF = -1;

	@Nested
	@TestInstance(TestInstance.Lifecycle.PER_CLASS)
	@EnabledOnOs(OS.WINDOWS)
	public class Windows {

		private FileSystem fileSystem;

		@BeforeAll
		public void setupClass(@TempDir Path tmpDir) throws IOException {
			fileSystem = new CryptoFileSystemProvider().newFileSystem(create(tmpDir), cryptoFileSystemProperties().withPassphrase("asd").build());
		}

		// tests https://github.com/cryptomator/cryptofs/issues/56
		@Test
		public void testForceDoesntBumpModifiedDate() throws IOException {
			Path file = fileSystem.getPath("/file.txt");

			Instant t0, t1;
			t0 = Instant.ofEpochSecond(123456789).truncatedTo(ChronoUnit.SECONDS);

			try (FileChannel ch = FileChannel.open(file, CREATE_NEW, WRITE)) {
				Files.setLastModifiedTime(file, FileTime.from(t0));
			}

			t1 = Files.getLastModifiedTime(file).toInstant().truncatedTo(ChronoUnit.SECONDS);
			Assertions.assertTrue(t1.equals(t0));
		}

	}

	@Nested
	@TestInstance(TestInstance.Lifecycle.PER_CLASS)
	public class PlatformIndependent {

		private FileSystem inMemoryFs;
		private FileSystem fileSystem;

		private Path file;

		@BeforeAll
		public void beforeAll() throws IOException {
			inMemoryFs = Jimfs.newFileSystem();
			Path vaultPath = inMemoryFs.getPath("/vault");
			Files.createDirectories(vaultPath);
			CryptoFileSystemProvider.initialize(vaultPath, "masterkey.cryptomator", "asd");
			fileSystem = new CryptoFileSystemProvider().newFileSystem(vaultPath, cryptoFileSystemProperties().withPassphrase("asd").withFlags().build());
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

		// tests https://github.com/cryptomator/cryptofs/issues/55
		@Test
		public void testCreateNewFileSetsLastModifiedToNow() throws IOException, InterruptedException {
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

	}

}
