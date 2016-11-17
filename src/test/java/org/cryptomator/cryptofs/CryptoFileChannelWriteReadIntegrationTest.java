/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptofs;

import static java.lang.Math.min;
import static java.lang.String.format;
import static java.nio.file.StandardOpenOption.APPEND;
import static java.nio.file.StandardOpenOption.CREATE;
import static java.nio.file.StandardOpenOption.READ;
import static java.nio.file.StandardOpenOption.WRITE;
import static org.cryptomator.cryptofs.CryptoFileSystemProperties.cryptoFileSystemProperties;
import static org.cryptomator.cryptofs.CryptoFileSystemUris.createUri;
import static org.cryptomator.cryptofs.util.ByteBuffers.repeat;
import static org.junit.Assert.assertEquals;
import static org.junit.Assume.assumeTrue;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.FileSystem;
import java.nio.file.Path;

import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.experimental.theories.DataPoints;
import org.junit.experimental.theories.FromDataPoints;
import org.junit.experimental.theories.Theories;
import org.junit.experimental.theories.Theory;
import org.junit.runner.RunWith;

import com.google.common.jimfs.Jimfs;

@RunWith(Theories.class)
public class CryptoFileChannelWriteReadIntegrationTest {

	private static final int EOF = -1;

	@DataPoints("dataSizes")
	public static int[] DATA_SIZES = {0, // nothing
			372, // nothing < x < full chunk
			32768, // x = full chunk
			40287, // full chunk < x < two chunks
			65536, // x = two chunks
			72389 // two chunks < x < three chunks
	};

	@DataPoints("writeOffsets")
	public static int[] WRITE_OFFSETS = {0, // nothing
			372, // nothing < x < full chunk
			32768, // x = full chunk
			40287, // full chunk < x < two chunks
			65536, // x = two chunks
			72389 // two chunks < x < three chunks
	};

	private static FileSystem inMemoryFs;
	private static Path pathToVault;
	private static FileSystem fileSystem;

	@BeforeClass
	public static void setupClass() throws IOException {
		inMemoryFs = Jimfs.newFileSystem();
		pathToVault = inMemoryFs.getRootDirectories().iterator().next().resolve("vault");
		fileSystem = new CryptoFileSystemProvider().newFileSystem(createUri(pathToVault), cryptoFileSystemProperties().withPassphrase("asd").build());
	}

	@AfterClass
	public static void teardownClass() throws IOException {
		inMemoryFs.close();
	}

	@Test
	public void testWriteAndReadNothing() throws IOException {
		long fileId = nextFileId();

		try (FileChannel channel = writableChannel(fileId)) {
			channel.write(ByteBuffer.allocate(0));
		}

		try (FileChannel channel = readableChannel(fileId)) {
			assertEquals(EOF, channel.read(ByteBuffer.allocate(0)));
		}
	}

	@Theory
	public void testWriteDataAndTruncateToOffset(@FromDataPoints("dataSizes") int cleartextSize, @FromDataPoints("writeOffsets") int truncateToSize) throws IOException {
		long fileId = nextFileId();

		int targetSize = min(truncateToSize, cleartextSize);

		try (FileChannel channel = writableChannel(fileId)) {
			assertEquals(0, channel.size());
			channel.write(repeat(1).times(cleartextSize).asByteBuffer());
			assertEquals(cleartextSize, channel.size());
		}

		try (FileChannel channel = writableChannel(fileId)) {
			assertEquals(cleartextSize, channel.size());
			channel.truncate(truncateToSize);
			assertEquals(targetSize, channel.size());
		}

		try (FileChannel channel = readableChannel(fileId)) {
			if (targetSize > 0) {
				ByteBuffer buffer = ByteBuffer.allocate(targetSize);
				int result = channel.read(buffer);
				assertEquals(targetSize, result);
				buffer.flip();
				for (int i = 0; i < targetSize; i++) {
					assertEquals(format("byte(%d) = 1", i), 1, buffer.get(i));
				}
			}
			assertEquals(EOF, channel.read(ByteBuffer.allocate(0)));
		}
	}

	@Theory
	public void testWithWritingOffset(@FromDataPoints("dataSizes") int dataSize, @FromDataPoints("writeOffsets") int writeOffset) throws IOException {
		assumeTrue(dataSize != 0 || writeOffset != 0);

		long fileId = nextFileId();

		int cleartextSize = dataSize + writeOffset;

		try (FileChannel channel = writableChannel(fileId)) {
			assertEquals(0, channel.size());
			channel.write(repeat(1).times(writeOffset).asByteBuffer());
			assertEquals(writeOffset, channel.size());
			channel.write(repeat(2).times(dataSize).asByteBuffer());
			assertEquals(cleartextSize, channel.size());
		}

		try (FileChannel channel = readableChannel(fileId)) {
			ByteBuffer buffer = ByteBuffer.allocate(cleartextSize);
			int result = channel.read(buffer);
			assertEquals(cleartextSize, result);
			assertEquals(EOF, channel.read(ByteBuffer.allocate(0)));
			buffer.flip();
			for (int i = 0; i < cleartextSize; i++) {
				if (i < writeOffset) {
					assertEquals(format("byte(%d) = 1", i), 1, buffer.get(i));
				} else {
					assertEquals(format("byte(%d) = 2", i), 2, buffer.get(i));
				}
			}
		}
	}

	@Theory
	public void testWithWritingInReverseOrderUsingPositions(@FromDataPoints("dataSizes") int dataSize, @FromDataPoints("writeOffsets") int writeOffset) throws IOException {
		assumeTrue(dataSize != 0 || writeOffset != 0);

		long fileId = nextFileId();

		int cleartextSize = dataSize + writeOffset;

		try (FileChannel channel = writableChannel(fileId)) {
			assertEquals(0, channel.size());
			channel.write(repeat(2).times(dataSize).asByteBuffer(), writeOffset);
			assertEquals(cleartextSize, channel.size());
			channel.write(repeat(1).times(writeOffset).asByteBuffer(), 0);
			assertEquals(cleartextSize, channel.size());
		}

		try (FileChannel channel = readableChannel(fileId)) {
			ByteBuffer buffer = ByteBuffer.allocate(cleartextSize);
			int result = channel.read(buffer);
			assertEquals(cleartextSize, result);
			assertEquals(EOF, channel.read(ByteBuffer.allocate(0)));
			buffer.flip();
			for (int i = 0; i < cleartextSize; i++) {
				if (i < writeOffset) {
					assertEquals(format("byte(%d) = 1", i), 1, buffer.get(i));
				} else {
					assertEquals(format("byte(%d) = 2", i), 2, buffer.get(i));
				}
			}
		}
	}

	@Theory
	public void testWithSkippingOffset(@FromDataPoints("dataSizes") int dataSize, @FromDataPoints("writeOffsets") int writeOffset) throws IOException {
		assumeTrue(dataSize != 0 && writeOffset != 0);

		long fileId = nextFileId();

		int cleartextSize = dataSize + writeOffset;

		try (FileChannel channel = writableChannel(fileId)) {
			assertEquals(0, channel.size());
			channel.position(writeOffset);
			channel.write(repeat(2).times(dataSize).asByteBuffer());
			assertEquals(cleartextSize, channel.size());
		}

		try (FileChannel channel = readableChannel(fileId)) {
			ByteBuffer buffer = ByteBuffer.allocate(cleartextSize);
			int result = channel.read(buffer);
			assertEquals(cleartextSize, result);
			assertEquals(EOF, channel.read(ByteBuffer.allocate(0)));
			buffer.flip();
			for (int i = writeOffset; i < cleartextSize; i++) {
				assertEquals(format("byte(%d) = 2", i), 2, buffer.get(i));
			}
		}
	}

	@Theory
	public void testAppend(@FromDataPoints("dataSizes") int dataSize, @FromDataPoints("writeOffsets") int writeOffset) throws IOException {
		assumeTrue(dataSize != 0 || writeOffset != 0);

		long fileId = nextFileId();

		int cleartextSize = dataSize + writeOffset;

		try (FileChannel channel = writableChannelInAppendMode(fileId)) {
			assertEquals(0, channel.size());
			if (writeOffset > 0) {
				channel.write(repeat(1).times(1).asByteBuffer(), writeOffset - 1);
				assertEquals(writeOffset, channel.size());
			}
			channel.write(repeat(2).times(dataSize).asByteBuffer());
			assertEquals(cleartextSize, channel.size());
		}

		try (FileChannel channel = readableChannel(fileId)) {
			ByteBuffer buffer = ByteBuffer.allocate(cleartextSize);
			int result = channel.read(buffer);
			assertEquals(cleartextSize, result);
			assertEquals(EOF, channel.read(ByteBuffer.allocate(0)));
			buffer.flip();
			for (int i = 0; i < cleartextSize; i++) {
				if (i >= writeOffset) {
					assertEquals(format("byte(%d) = 2", i), 2, buffer.get(i));
				} else if (i == writeOffset - 1) {
					assertEquals(format("byte(%d) = 1", i), 1, buffer.get(i));
				}
			}
		}
	}

	private static long nextFileId = 1;

	private long nextFileId() {
		return nextFileId++;
	}

	private FileChannel readableChannel(long fileId) throws IOException {
		return FileChannel.open(fileSystem.getPath("/test" + fileId + ".file"), READ);
	}

	private FileChannel writableChannel(long fileId) throws IOException {
		return FileChannel.open(fileSystem.getPath("/test" + fileId + ".file"), CREATE, WRITE);
	}

	private FileChannel writableChannelInAppendMode(long fileId) throws IOException {
		return FileChannel.open(fileSystem.getPath("/test" + fileId + ".file"), CREATE, WRITE, APPEND);
	}

}
