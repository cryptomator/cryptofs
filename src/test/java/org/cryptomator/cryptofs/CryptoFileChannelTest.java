/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptofs;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HashSet;

import org.cryptomator.cryptolib.Cryptor;
import org.cryptomator.cryptolib.CryptorProvider;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

public class CryptoFileChannelTest {

	private static final SecureRandom NULL_RANDOM = new SecureRandom() {
		@Override
		public synchronized void nextBytes(byte[] bytes) {
			Arrays.fill(bytes, (byte) 0x00);
		};
	};
	private static final CryptorProvider NULL_CRYPTOR_PROVIDER = new CryptorProvider(NULL_RANDOM);

	private Cryptor cryptor;
	private Path ciphertextFilePath;

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
	public void testWriteAndRead() throws IOException {
		try (CryptoFileChannel ch = new CryptoFileChannel(cryptor, ciphertextFilePath, new HashSet<>(Arrays.asList(StandardOpenOption.CREATE, StandardOpenOption.WRITE)))) {
			Assert.assertEquals(0l, ch.size());
			ch.write(ByteBuffer.allocate(32 * 1024));
			Assert.assertEquals(32l * 1024, ch.size());
			ch.write(ByteBuffer.allocate(32 * 1024));
			Assert.assertEquals(64l * 1024, ch.size());
			ch.write(ByteBuffer.wrap("hello".getBytes()), 64 * 1024);
			ch.write(ByteBuffer.wrap("world".getBytes()), 64 * 1024);
			Assert.assertEquals(64l * 1024 + 5, ch.size());
			ch.write(ByteBuffer.wrap("hello world".getBytes()), 64 * 1024);
			Assert.assertEquals(64l * 1024 + 11, ch.size());
		}

		Assert.assertEquals(88 + 2 * (16 + 32 * 1024 + 32) + 16 + 11 + 32, Files.size(ciphertextFilePath));

		// random access:
		try (CryptoFileChannel ch = new CryptoFileChannel(cryptor, ciphertextFilePath, new HashSet<>(Arrays.asList(StandardOpenOption.READ)))) {
			ByteBuffer helloWorldBuffer = ByteBuffer.allocate(14);
			Assert.assertEquals(11, ch.read(helloWorldBuffer, 64l * 1024));
			Assert.assertArrayEquals("hello world\0\0\0".getBytes(), helloWorldBuffer.array());
		}

		// sequential:
		try (CryptoFileChannel ch = new CryptoFileChannel(cryptor, ciphertextFilePath, new HashSet<>(Arrays.asList(StandardOpenOption.READ)))) {
			Assert.assertEquals(64l * 1024 + 11, ch.size());
			ch.read(ByteBuffer.allocate(64 * 1024));
			ByteBuffer helloWorldBuffer = ByteBuffer.allocate(14);
			Assert.assertEquals(11, ch.read(helloWorldBuffer));
			Assert.assertArrayEquals("hello world\0\0\0".getBytes(), helloWorldBuffer.array());
		}
	}

}
