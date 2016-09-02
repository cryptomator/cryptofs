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
import static java.nio.file.Files.size;
import static java.nio.file.StandardOpenOption.APPEND;
import static java.nio.file.StandardOpenOption.CREATE;
import static java.nio.file.StandardOpenOption.READ;
import static java.nio.file.StandardOpenOption.WRITE;
import static java.util.Arrays.asList;
import static org.cryptomator.cryptofs.OpenCryptoFile.anOpenCryptoFile;
import static org.junit.Assert.assertEquals;
import static org.junit.Assume.assumeTrue;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.ClosedChannelException;
import java.nio.file.Files;
import java.nio.file.OpenOption;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HashSet;

import org.cryptomator.cryptolib.api.Cryptor;
import org.cryptomator.cryptolib.api.CryptorProvider;
import org.cryptomator.cryptolib.v1.CryptorProviderImpl;
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

	private static final int HEADER_SIZE = 88;

	private static final int CHUNK_SIZE = 32 * 1024;

	private static final int CHUNK_OVERHEAD = 16 + 32;

	private static final int EOF = -1;

	private static final SecureRandom NULL_RANDOM = new SecureRandom() {
		@Override
		public synchronized void nextBytes(byte[] bytes) {
			Arrays.fill(bytes, (byte) 0x00);
		};
	};

	private static final CryptorProvider NULL_CRYPTOR_PROVIDER = new CryptorProviderImpl(NULL_RANDOM);

	private Cryptor cryptor;
	private Path ciphertextFilePath;

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

	@Before
	public void setup() throws IOException {
		cryptor = NULL_CRYPTOR_PROVIDER.createNew();
		ciphertextFilePath = Files.createTempFile("unittest", null);
	}

	@After
	public void teardown() throws IOException {
		Files.deleteIfExists(ciphertextFilePath);
	}

	@Test
	public void testWriteAndReadNothing() throws IOException {
		try (CryptoFileChannel channel = writableChannel()) {
			channel.write(ByteBuffer.allocate(0));
		}

		assertEquals(HEADER_SIZE, size(ciphertextFilePath));

		try (CryptoFileChannel channel = readableChannel()) {
			assertEquals(EOF, channel.read(ByteBuffer.allocate(0)));
		}
	}

	@Theory
	public void testWithWritingOffset(@FromDataPoints("dataSizes") int dataSize, @FromDataPoints("writeOffsets") int writeOffset) throws IOException {
		assumeTrue(dataSize != 0 || writeOffset != 0);

		int cleartextSize = dataSize + writeOffset;
		int numChunks = (cleartextSize + CHUNK_SIZE - 1) / CHUNK_SIZE;
		int ciphertextSize = HEADER_SIZE + numChunks * CHUNK_OVERHEAD + writeOffset + dataSize;

		try (CryptoFileChannel channel = writableChannel()) {
			assertEquals(0, channel.size());
			channel.write(repeat(1).times(writeOffset).asByteBuffer());
			assertEquals(writeOffset, channel.size());
			channel.write(repeat(2).times(dataSize).asByteBuffer());
			assertEquals(cleartextSize, channel.size());
		}

		assertEquals(ciphertextSize, size(ciphertextFilePath));

		try (CryptoFileChannel channel = readableChannel()) {
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
		int numChunks = (cleartextSize + CHUNK_SIZE - 1) / CHUNK_SIZE;
		int ciphertextSize = HEADER_SIZE + numChunks * CHUNK_OVERHEAD + writeOffset + dataSize;

		try (CryptoFileChannel channel = writableChannel()) {
			assertEquals(0, channel.size());
			channel.write(repeat(2).times(dataSize).asByteBuffer(), writeOffset);
			assertEquals(cleartextSize, channel.size());
			channel.write(repeat(1).times(writeOffset).asByteBuffer(), 0);
			assertEquals(cleartextSize, channel.size());
		}

		assertEquals(ciphertextSize, size(ciphertextFilePath));

		try (CryptoFileChannel channel = readableChannel()) {
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
		int numChunks = (cleartextSize + CHUNK_SIZE - 1) / CHUNK_SIZE;
		int ciphertextSize = HEADER_SIZE + numChunks * CHUNK_OVERHEAD + writeOffset + dataSize;

		try (CryptoFileChannel channel = writableChannel()) {
			assertEquals(0, channel.size());
			channel.position(writeOffset);
			channel.write(repeat(2).times(dataSize).asByteBuffer());
			assertEquals(cleartextSize, channel.size());
		}

		assertEquals(ciphertextSize, size(ciphertextFilePath));

		try (CryptoFileChannel channel = readableChannel()) {
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
		int numChunks = (cleartextSize + CHUNK_SIZE - 1) / CHUNK_SIZE;
		int ciphertextSize = HEADER_SIZE + numChunks * CHUNK_OVERHEAD + writeOffset + dataSize;

		try (CryptoFileChannel channel = writableChannelInAppendMode()) {
			assertEquals(0, channel.size());
			if (writeOffset > 0) {
				channel.write(repeat(1).times(1).asByteBuffer(), writeOffset - 1);
				assertEquals(writeOffset, channel.size());
			}
			channel.write(repeat(2).times(dataSize).asByteBuffer());
			assertEquals(cleartextSize, channel.size());
		}

		assertEquals(ciphertextSize, size(ciphertextFilePath));

		try (CryptoFileChannel channel = readableChannel()) {
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

	private CryptoFileChannel readableChannel() throws IOException {
		EffectiveOpenOptions options = options(READ);
		OpenCryptoFile openCryptoFile = anOpenCryptoFile() //
				.withCryptor(cryptor) //
				.withPath(ciphertextFilePath) //
				.withOptions(options) //
				.build();
		try {
			openCryptoFile.open(options);
			return new CryptoFileChannel(openCryptoFile, options);
		} catch (ClosedChannelException e) {
			throw new IllegalStateException(e);
		}
	}

	private CryptoFileChannel writableChannel() throws IOException {
		EffectiveOpenOptions options = options(CREATE, WRITE);
		OpenCryptoFile openCryptoFile = anOpenCryptoFile() //
				.withCryptor(cryptor) //
				.withPath(ciphertextFilePath) //
				.withOptions(options) //
				.build();
		try {
			openCryptoFile.open(options);
			return new CryptoFileChannel(openCryptoFile, options);
		} catch (ClosedChannelException e) {
			throw new IllegalStateException(e);
		}
	}

	private CryptoFileChannel writableChannelInAppendMode() throws IOException {
		EffectiveOpenOptions options = options(CREATE, WRITE, APPEND);
		OpenCryptoFile openCryptoFile = anOpenCryptoFile() //
				.withCryptor(cryptor) //
				.withPath(ciphertextFilePath) //
				.withOptions(options) //
				.build();
		try {
			openCryptoFile.open(options);
			return new CryptoFileChannel(openCryptoFile, options);
		} catch (ClosedChannelException e) {
			throw new IllegalStateException(e);
		}
	}

	private EffectiveOpenOptions options(OpenOption... options) {
		return EffectiveOpenOptions.from(new HashSet<>(asList(options)));
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
