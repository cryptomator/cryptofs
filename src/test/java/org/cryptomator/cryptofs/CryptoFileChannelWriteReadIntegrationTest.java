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
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.FileSystem;
import java.nio.file.Files;
import java.nio.file.Path;

import static java.lang.Math.min;
import static java.lang.String.format;
import static java.nio.file.StandardOpenOption.APPEND;
import static java.nio.file.StandardOpenOption.CREATE;
import static java.nio.file.StandardOpenOption.READ;
import static java.nio.file.StandardOpenOption.WRITE;
import static org.cryptomator.cryptofs.CryptoFileSystemProperties.cryptoFileSystemProperties;
import static org.cryptomator.cryptofs.CryptoFileSystemUri.create;
import static org.cryptomator.cryptofs.util.ByteBuffers.repeat;

public class CryptoFileChannelWriteReadIntegrationTest {

	private static final int EOF = -1;

	private static FileSystem inMemoryFs;
	private static Path pathToVault;
	private static FileSystem fileSystem;

	@BeforeAll
	public static void setupClass() throws IOException {
		inMemoryFs = Jimfs.newFileSystem();
		pathToVault = inMemoryFs.getRootDirectories().iterator().next().resolve("vault");
		Files.createDirectory(pathToVault);
		fileSystem = new CryptoFileSystemProvider().newFileSystem(create(pathToVault), cryptoFileSystemProperties().withPassphrase("asd").build());
	}

	@AfterAll
	public static void teardownClass() throws IOException {
		inMemoryFs.close();
	}

	// tests https://github.com/cryptomator/cryptofs/issues/22
	@Test
	public void testFileSizeIsZeroAfterCreatingFileChannel() throws IOException {
		long fileId = nextFileId();

		try (FileChannel channel = writableChannel(fileId)) {
			Assertions.assertEquals(0, channel.size());
			Assertions.assertEquals(0, Files.size(filePath(fileId)));
		}
	}

	// tests https://github.com/cryptomator/cryptofs/issues/26
	@Test
	public void testFileSizeIsTenAfterWritingTenBytes() throws IOException {
		long fileId = nextFileId();

		try (FileChannel channel = writableChannel(fileId)) {
			channel.write(ByteBuffer.wrap(new byte[10]));
			Assertions.assertEquals(10, channel.size());
			Assertions.assertEquals(10, Files.size(filePath(fileId)));
		}
	}

	@Test
	public void testWriteAndReadNothing() throws IOException {
		long fileId = nextFileId();

		try (FileChannel channel = writableChannel(fileId)) {
			channel.write(ByteBuffer.allocate(0));
		}

		try (FileChannel channel = readableChannel(fileId)) {
			Assertions.assertEquals(EOF, channel.read(ByteBuffer.allocate(0)));
		}
	}

	@ParameterizedTest(name = "write {0} bytes and truncate to {1}")
	@CsvSource({"0, 0", "0, 5000", "0, 32768", "0, 40000", "70000, 0", "70000, 30000", "70000, 40000", "70000, 65536", "70000, 80000"})
	public void testWriteDataAndTruncateToOffset(int cleartextSize, int truncateToSize) throws IOException {
		long fileId = nextFileId();

		int targetSize = min(truncateToSize, cleartextSize);

		try (FileChannel channel = writableChannel(fileId)) {
			Assertions.assertEquals(0, channel.size());
			channel.write(repeat(1).times(cleartextSize).asByteBuffer());
			Assertions.assertEquals(cleartextSize, channel.size());
		}

		try (FileChannel channel = writableChannel(fileId)) {
			Assertions.assertEquals(cleartextSize, channel.size());
			channel.truncate(truncateToSize);
			Assertions.assertEquals(targetSize, channel.size());
		}

		try (FileChannel channel = readableChannel(fileId)) {
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
		long fileId = nextFileId();

		int cleartextSize = dataSize + writeOffset;

		try (FileChannel channel = writableChannel(fileId)) {
			Assertions.assertEquals(0, channel.size());
			channel.write(repeat(1).times(writeOffset).asByteBuffer());
			Assertions.assertEquals(writeOffset, channel.size());
			channel.write(repeat(2).times(dataSize).asByteBuffer());
			Assertions.assertEquals(cleartextSize, channel.size());
		}

		try (FileChannel channel = readableChannel(fileId)) {
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
		long fileId = nextFileId();

		int cleartextSize = dataSize + writeOffset;

		try (FileChannel channel = writableChannel(fileId)) {
			Assertions.assertEquals(0, channel.size());
			channel.write(repeat(2).times(dataSize).asByteBuffer(), writeOffset);
			Assertions.assertEquals(cleartextSize, channel.size());
			channel.write(repeat(1).times(writeOffset).asByteBuffer(), 0);
			Assertions.assertEquals(cleartextSize, channel.size());
		}

		try (FileChannel channel = readableChannel(fileId)) {
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
		long fileId = nextFileId();

		int cleartextSize = dataSize + writeOffset;

		try (FileChannel channel = writableChannel(fileId)) {
			Assertions.assertEquals(0, channel.size());
			channel.position(writeOffset);
			channel.write(repeat(2).times(dataSize).asByteBuffer());
			Assertions.assertEquals(cleartextSize, channel.size());
		}

		Assertions.assertEquals(cleartextSize, Files.size(filePath(fileId)));

		try (FileChannel channel = readableChannel(fileId)) {
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
		long fileId = nextFileId();

		try (FileChannel channel = writableChannelInAppendMode(fileId)) {
			Assertions.assertEquals(0, channel.size());
			channel.write(repeat(1).times(dataSize).asByteBuffer());
			Assertions.assertEquals(dataSize, channel.size());
		}

		try (FileChannel channel = writableChannelInAppendMode(fileId)) {
			Assertions.assertEquals(dataSize, channel.size());
			channel.write(repeat(1).times(dataSize).asByteBuffer());
			channel.write(repeat(1).times(dataSize).asByteBuffer());
			Assertions.assertEquals(3*dataSize, channel.size());
		}

		try (FileChannel channel = readableChannel(fileId)) {
			ByteBuffer buffer = ByteBuffer.allocate(3*dataSize);
			int result = channel.read(buffer);
			Assertions.assertEquals(3*dataSize, result);
			Assertions.assertEquals(EOF, channel.read(ByteBuffer.allocate(0)));
		}
	}

	private static long nextFileId = 1;

	private long nextFileId() {
		return nextFileId++;
	}

	private Path filePath(long fileId) {
		return fileSystem.getPath("/test" + fileId + ".file");
	}

	private FileChannel readableChannel(long fileId) throws IOException {
		return FileChannel.open(filePath(fileId), READ);
	}

	private FileChannel writableChannel(long fileId) throws IOException {
		return FileChannel.open(filePath(fileId), CREATE, WRITE);
	}

	private FileChannel writableChannelInAppendMode(long fileId) throws IOException {
		return FileChannel.open(filePath(fileId), CREATE, WRITE, APPEND);
	}

}
