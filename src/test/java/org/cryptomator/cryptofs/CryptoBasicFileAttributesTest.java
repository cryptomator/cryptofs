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
import java.io.UncheckedIOException;
import java.nio.ByteBuffer;
import java.nio.file.FileSystem;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.spi.FileSystemProvider;
import java.security.SecureRandom;
import java.util.Arrays;

import org.cryptomator.cryptolib.api.CryptorProvider;
import org.cryptomator.cryptolib.api.FileHeader;
import org.cryptomator.cryptolib.api.FileHeaderCryptor;
import org.cryptomator.cryptolib.v1.CryptorProviderImpl;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;

public class CryptoBasicFileAttributesTest {

	private static final SecureRandom NULL_RANDOM = new SecureRandom() {
		@Override
		public synchronized void nextBytes(byte[] bytes) {
			Arrays.fill(bytes, (byte) 0x00);
		};
	};
	private static final CryptorProvider CRYPTOR_PROVIDER = new CryptorProviderImpl(NULL_RANDOM);

	private FileHeaderCryptor fileHeaderCryptor;
	private Path ciphertextFilePath;
	private BasicFileAttributes delegateAttr;
	private FileSystemProvider fsProvider;

	@Before
	public void setup() throws IOException {
		fileHeaderCryptor = CRYPTOR_PROVIDER.createNew().fileHeaderCryptor();
		ciphertextFilePath = Mockito.mock(Path.class);
		FileSystem fs = Mockito.mock(FileSystem.class);
		Mockito.when(ciphertextFilePath.getFileSystem()).thenReturn(fs);
		fsProvider = Mockito.mock(FileSystemProvider.class);
		Mockito.when(fs.provider()).thenReturn(fsProvider);
		delegateAttr = Mockito.mock(BasicFileAttributes.class);
	}

	@Test
	public void testIsDirectory() {
		BasicFileAttributes attr = new CryptoBasicFileAttributes(delegateAttr, ciphertextFilePath, fileHeaderCryptor);

		Mockito.when(delegateAttr.isRegularFile()).thenReturn(true);
		Mockito.when(ciphertextFilePath.getFileName()).thenReturn(Paths.get("foo"));
		Assert.assertFalse(attr.isDirectory());

		Mockito.when(delegateAttr.isRegularFile()).thenReturn(true);
		Mockito.when(ciphertextFilePath.getFileName()).thenReturn(Paths.get("0foo"));
		Assert.assertTrue(attr.isDirectory());

		Mockito.when(delegateAttr.isRegularFile()).thenReturn(false);
		Mockito.when(ciphertextFilePath.getFileName()).thenReturn(Paths.get("foo"));
		Assert.assertFalse(attr.isRegularFile());

		Mockito.when(delegateAttr.isRegularFile()).thenReturn(false);
		Mockito.when(ciphertextFilePath.getFileName()).thenReturn(Paths.get("0foo"));
		Assert.assertFalse(attr.isRegularFile());
	}

	@Test
	public void testIsRegularFile() {
		BasicFileAttributes attr = new CryptoBasicFileAttributes(delegateAttr, ciphertextFilePath, fileHeaderCryptor);

		Mockito.when(delegateAttr.isRegularFile()).thenReturn(true);
		Mockito.when(ciphertextFilePath.getFileName()).thenReturn(Paths.get("foo"));
		Assert.assertTrue(attr.isRegularFile());

		Mockito.when(delegateAttr.isRegularFile()).thenReturn(true);
		Mockito.when(ciphertextFilePath.getFileName()).thenReturn(Paths.get("0foo"));
		Assert.assertFalse(attr.isRegularFile());

		Mockito.when(delegateAttr.isRegularFile()).thenReturn(false);
		Mockito.when(ciphertextFilePath.getFileName()).thenReturn(Paths.get("foo"));
		Assert.assertFalse(attr.isRegularFile());

		Mockito.when(delegateAttr.isRegularFile()).thenReturn(false);
		Mockito.when(ciphertextFilePath.getFileName()).thenReturn(Paths.get("0foo"));
		Assert.assertFalse(attr.isRegularFile());
	}

	@Test
	public void testIsOther() {
		BasicFileAttributes attr = new CryptoBasicFileAttributes(delegateAttr, ciphertextFilePath, fileHeaderCryptor);
		Assert.assertFalse(attr.isOther());
	}

	@Test
	public void testIsSymbolicLink() {
		BasicFileAttributes attr = new CryptoBasicFileAttributes(delegateAttr, ciphertextFilePath, fileHeaderCryptor);
		Assert.assertFalse(attr.isSymbolicLink());
	}

	@Test
	public void testSize() throws IOException {
		FileHeader header = fileHeaderCryptor.create();
		header.setFilesize(1337l);
		ByteBuffer headerBuf = fileHeaderCryptor.encryptHeader(header);
		Mockito.when(fsProvider.newByteChannel(Mockito.same(ciphertextFilePath), Mockito.any())).thenReturn(new SeekableByteChannelMock(headerBuf));
		Mockito.when(ciphertextFilePath.getFileName()).thenReturn(Paths.get("foo"));
		Mockito.when(delegateAttr.size()).thenReturn((long) headerBuf.capacity());
		Mockito.when(delegateAttr.isRegularFile()).thenReturn(true);

		BasicFileAttributes attr = new CryptoBasicFileAttributes(delegateAttr, ciphertextFilePath, fileHeaderCryptor);
		Assert.assertEquals(1337l, attr.size());
	}

	@Test(expected = UncheckedIOException.class)
	public void testSizeWithException() throws IOException {
		FileHeader header = fileHeaderCryptor.create();
		header.setFilesize(1337l);
		ByteBuffer headerBuf = fileHeaderCryptor.encryptHeader(header);
		Mockito.when(fsProvider.newByteChannel(Mockito.same(ciphertextFilePath), Mockito.any())).thenThrow(new IOException("fail"));
		Mockito.when(ciphertextFilePath.getFileName()).thenReturn(Paths.get("foo"));
		Mockito.when(delegateAttr.size()).thenReturn((long) headerBuf.capacity());
		Mockito.when(delegateAttr.isRegularFile()).thenReturn(true);

		BasicFileAttributes attr = new CryptoBasicFileAttributes(delegateAttr, ciphertextFilePath, fileHeaderCryptor);
		attr.size();
	}

}
