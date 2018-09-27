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
import java.nio.file.FileSystem;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.spi.FileSystemProvider;
import java.util.Optional;

import org.cryptomator.cryptolib.api.Cryptor;
import org.cryptomator.cryptolib.api.FileContentCryptor;
import org.cryptomator.cryptolib.api.FileHeaderCryptor;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;

public class CryptoBasicFileAttributesTest {

	private Cryptor cryptor;
	private Path ciphertextFilePath;
	private BasicFileAttributes delegateAttr;

	@Before
	public void setup() throws IOException {
		cryptor = Mockito.mock(Cryptor.class);
		FileHeaderCryptor headerCryptor = Mockito.mock(FileHeaderCryptor.class);
		FileContentCryptor contentCryptor = Mockito.mock(FileContentCryptor.class);
		Mockito.when(cryptor.fileHeaderCryptor()).thenReturn(headerCryptor);
		Mockito.when(headerCryptor.headerSize()).thenReturn(88);
		Mockito.when(cryptor.fileContentCryptor()).thenReturn(contentCryptor);
		Mockito.when(contentCryptor.cleartextChunkSize()).thenReturn(32 * 1024);
		Mockito.when(contentCryptor.ciphertextChunkSize()).thenReturn(16 + 32 * 1024 + 32);
		ciphertextFilePath = Mockito.mock(Path.class);
		FileSystem fs = Mockito.mock(FileSystem.class);
		Mockito.when(ciphertextFilePath.getFileSystem()).thenReturn(fs);
		FileSystemProvider fsProvider = Mockito.mock(FileSystemProvider.class);
		Mockito.when(fs.provider()).thenReturn(fsProvider);
		delegateAttr = Mockito.mock(BasicFileAttributes.class);
	}

	@Test
	public void testIsDirectory() {
		BasicFileAttributes attr = new CryptoBasicFileAttributes(delegateAttr, ciphertextFilePath, cryptor, Optional.empty());

		Mockito.when(delegateAttr.isDirectory()).thenReturn(false);
		Assert.assertFalse(attr.isDirectory());

		Mockito.when(delegateAttr.isDirectory()).thenReturn(true);
		Assert.assertTrue(attr.isDirectory());
	}

	@Test
	public void testIsRegularFile() {
		BasicFileAttributes attr = new CryptoBasicFileAttributes(delegateAttr, ciphertextFilePath, cryptor, Optional.empty());

		Mockito.when(delegateAttr.isRegularFile()).thenReturn(true);
		Assert.assertTrue(attr.isRegularFile());

		Mockito.when(delegateAttr.isRegularFile()).thenReturn(false);
		Assert.assertFalse(attr.isRegularFile());
	}

	@Test
	public void testIsOther() {
		BasicFileAttributes attr = new CryptoBasicFileAttributes(delegateAttr, ciphertextFilePath, cryptor, Optional.empty());
		Assert.assertFalse(attr.isOther());
	}

	@Test
	public void testIsSymbolicLink() {
		BasicFileAttributes attr = new CryptoBasicFileAttributes(delegateAttr, ciphertextFilePath, cryptor, Optional.empty());
		Assert.assertFalse(attr.isSymbolicLink());
	}

	@Test
	public void testSizeOfFile() throws IOException {
		Mockito.when(delegateAttr.size()).thenReturn(88l + 16 + 1337 + 32);
		Mockito.when(delegateAttr.isDirectory()).thenReturn(false);
		Mockito.when(delegateAttr.isSymbolicLink()).thenReturn(false);
		Mockito.when(delegateAttr.isOther()).thenReturn(false);
		Mockito.when(ciphertextFilePath.getFileName()).thenReturn(Paths.get("foo"));

		BasicFileAttributes attr = new CryptoBasicFileAttributes(delegateAttr, ciphertextFilePath, cryptor, Optional.empty());

		Assert.assertEquals(1337l, attr.size());
	}

	@Test
	public void testSizeOfOpenFile() throws IOException {
		OpenCryptoFile openCryptoFile = Mockito.mock(OpenCryptoFile.class);
		Mockito.when(delegateAttr.isDirectory()).thenReturn(false);
		Mockito.when(delegateAttr.isSymbolicLink()).thenReturn(false);
		Mockito.when(delegateAttr.isOther()).thenReturn(false);
		Mockito.when(ciphertextFilePath.getFileName()).thenReturn(Paths.get("foo"));
		Mockito.when(openCryptoFile.size()).thenReturn(1338l);

		BasicFileAttributes attr = new CryptoBasicFileAttributes(delegateAttr, ciphertextFilePath, cryptor, Optional.of(openCryptoFile));

		Assert.assertEquals(1338l, attr.size());
		Mockito.verify(delegateAttr, Mockito.never()).size();
	}

	@Test
	public void testSizeOfDirectory() throws IOException {
		Mockito.when(delegateAttr.size()).thenReturn(4096l);
		Mockito.when(delegateAttr.isDirectory()).thenReturn(true);

		BasicFileAttributes attr = new CryptoBasicFileAttributes(delegateAttr, ciphertextFilePath, cryptor, Optional.empty());

		Assert.assertEquals(4096l, attr.size());
	}

	@Test
	public void testSizeSetToZeroIfCryptoHeaderToSmall() throws IOException {
		Mockito.when(delegateAttr.size()).thenReturn(88l + 20l);
		Mockito.when(delegateAttr.isRegularFile()).thenReturn(true);
		Mockito.when(ciphertextFilePath.getFileName()).thenReturn(Paths.get("foo"));

		BasicFileAttributes attr = new CryptoBasicFileAttributes(delegateAttr, ciphertextFilePath, cryptor, Optional.empty());
		Assert.assertEquals(attr.size(),0);
	}

}
