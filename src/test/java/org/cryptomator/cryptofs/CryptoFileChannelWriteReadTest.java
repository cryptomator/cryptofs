/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptofs;

import static java.lang.String.format;
import static java.nio.file.Files.walkFileTree;
import static java.nio.file.StandardOpenOption.APPEND;
import static java.nio.file.StandardOpenOption.CREATE;
import static java.nio.file.StandardOpenOption.READ;
import static java.nio.file.StandardOpenOption.WRITE;
import static org.cryptomator.cryptofs.CryptoFileSystemProperties.cryptoFileSystemProperties;
import static org.cryptomator.cryptofs.CryptoFileSystemUris.createUri;
import static org.junit.Assert.assertEquals;
import static org.junit.Assume.assumeTrue;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.FileSystem;
import java.nio.file.Files;
import java.nio.file.Path;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.experimental.theories.DataPoints;
import org.junit.experimental.theories.FromDataPoints;
import org.junit.experimental.theories.Theories;
import org.junit.experimental.theories.Theory;
import org.junit.runner.RunWith;

@RunWith(Theories.class)
public class CryptoFileChannelWriteReadTest {

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

	private Path pathToVault;
	private FileSystem fileSystem;

	@Before
	public void setup() throws IOException {
		CryptoFileSystemProvider provider = new CryptoFileSystemProvider();
		pathToVault = Files.createTempDirectory("CryptoFileChannelWriteReadTest").toAbsolutePath();
		fileSystem = provider.newFileSystem(createUri(pathToVault), cryptoFileSystemProperties().withPassphrase("asd").build());
	}

	@After
	public void teardown() throws IOException {
		walkFileTree(pathToVault, new DeletingFileVisitor());
	}

	@Test
	public void testWriteAndReadNothing() throws IOException {
		try (FileChannel channel = writableChannel()) {
			channel.write(ByteBuffer.allocate(0));
		}

		try (FileChannel channel = readableChannel()) {
			assertEquals(EOF, channel.read(ByteBuffer.allocate(0)));
		}
	}

	@Theory
	public void testWithWritingOffset(@FromDataPoints("dataSizes") int dataSize, @FromDataPoints("writeOffsets") int writeOffset) throws IOException {
		assumeTrue(dataSize != 0 || writeOffset != 0);

		int cleartextSize = dataSize + writeOffset;

		try (FileChannel channel = writableChannel()) {
			assertEquals(0, channel.size());
			channel.write(repeat(1).times(writeOffset).asByteBuffer());
			assertEquals(writeOffset, channel.size());
			channel.write(repeat(2).times(dataSize).asByteBuffer());
			assertEquals(cleartextSize, channel.size());
		}

		try (FileChannel channel = readableChannel()) {
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

		int cleartextSize = dataSize + writeOffset;

		try (FileChannel channel = writableChannel()) {
			assertEquals(0, channel.size());
			channel.write(repeat(2).times(dataSize).asByteBuffer(), writeOffset);
			assertEquals(cleartextSize, channel.size());
			channel.write(repeat(1).times(writeOffset).asByteBuffer(), 0);
			assertEquals(cleartextSize, channel.size());
		}

		try (FileChannel channel = readableChannel()) {
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

		int cleartextSize = dataSize + writeOffset;

		try (FileChannel channel = writableChannel()) {
			assertEquals(0, channel.size());
			channel.position(writeOffset);
			channel.write(repeat(2).times(dataSize).asByteBuffer());
			assertEquals(cleartextSize, channel.size());
		}

		try (FileChannel channel = readableChannel()) {
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

		int cleartextSize = dataSize + writeOffset;

		try (FileChannel channel = writableChannelInAppendMode()) {
			assertEquals(0, channel.size());
			if (writeOffset > 0) {
				channel.write(repeat(1).times(1).asByteBuffer(), writeOffset - 1);
				assertEquals(writeOffset, channel.size());
			}
			channel.write(repeat(2).times(dataSize).asByteBuffer());
			assertEquals(cleartextSize, channel.size());
		}

		try (FileChannel channel = readableChannel()) {
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

	private FileChannel readableChannel() throws IOException {
		return FileChannel.open(fileSystem.getPath("/test.file"), READ);
	}

	private FileChannel writableChannel() throws IOException {
		return FileChannel.open(fileSystem.getPath("/test.file"), CREATE, WRITE);
	}

	private FileChannel writableChannelInAppendMode() throws IOException {
		return FileChannel.open(fileSystem.getPath("/test.file"), CREATE, WRITE, APPEND);
	}

	public static RepeatWithoutCount repeat(int value) {
		return count -> () -> {
			ByteBuffer buffer = ByteBuffer.allocate(count);
			while (buffer.hasRemaining()) {
				buffer.put((byte) value);
			}
			buffer.flip();
			return buffer;
		};
	}

	public interface RepeatWithoutCount {

		ByteBufferFactory times(int count);

	}

	public interface ByteBufferFactory {

		ByteBuffer asByteBuffer();

	}

}
