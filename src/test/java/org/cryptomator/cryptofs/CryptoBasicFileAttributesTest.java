/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptofs;

import org.cryptomator.cryptolib.api.Cryptor;
import org.cryptomator.cryptolib.api.FileContentCryptor;
import org.cryptomator.cryptolib.api.FileHeaderCryptor;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;

import java.nio.file.FileSystem;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.spi.FileSystemProvider;
import java.util.Optional;

import static org.cryptomator.cryptofs.CryptoPathMapper.CiphertextFileType.DIRECTORY;
import static org.cryptomator.cryptofs.CryptoPathMapper.CiphertextFileType.FILE;
import static org.cryptomator.cryptofs.CryptoPathMapper.CiphertextFileType.SYMLINK;

public class CryptoBasicFileAttributesTest {

	private Cryptor cryptor;
	private Path ciphertextFilePath;
	private BasicFileAttributes delegateAttr;

	@Before
	public void setup() {
		cryptor = Mockito.mock(Cryptor.class);
		FileHeaderCryptor headerCryptor = Mockito.mock(FileHeaderCryptor.class);
		FileContentCryptor contentCryptor = Mockito.mock(FileContentCryptor.class);
		Mockito.when(cryptor.fileHeaderCryptor()).thenReturn(headerCryptor);
		Mockito.when(headerCryptor.headerSize()).thenReturn(88);
		Mockito.when(cryptor.fileContentCryptor()).thenReturn(contentCryptor);
		Mockito.when(contentCryptor.cleartextChunkSize()).thenReturn(32 * 1024);
		Mockito.when(contentCryptor.ciphertextChunkSize()).thenReturn(16 + 32 * 1024 + 32);
		ciphertextFilePath = Mockito.mock(Path.class, "ciphertextFile");
		delegateAttr = Mockito.mock(BasicFileAttributes.class);
	}

	@Test
	public void testIsDirectory() {
		BasicFileAttributes attr = new CryptoBasicFileAttributes(delegateAttr, DIRECTORY, ciphertextFilePath, cryptor, Optional.empty(), false);
		Assert.assertFalse(attr.isRegularFile());
		Assert.assertTrue(attr.isDirectory());
		Assert.assertFalse(attr.isSymbolicLink());
		Assert.assertFalse(attr.isOther());
	}

	@Test
	public void testIsRegularFile() {
		BasicFileAttributes attr = new CryptoBasicFileAttributes(delegateAttr, FILE, ciphertextFilePath, cryptor, Optional.empty(), false);
		Assert.assertTrue(attr.isRegularFile());
		Assert.assertFalse(attr.isDirectory());
		Assert.assertFalse(attr.isSymbolicLink());
		Assert.assertFalse(attr.isOther());
	}

	@Test
	public void testIsSymbolicLink() {
		BasicFileAttributes attr = new CryptoBasicFileAttributes(delegateAttr, SYMLINK, ciphertextFilePath, cryptor, Optional.empty(), false);
		Assert.assertFalse(attr.isRegularFile());
		Assert.assertFalse(attr.isDirectory());
		Assert.assertTrue(attr.isSymbolicLink());
		Assert.assertFalse(attr.isOther());
	}

	@Test
	public void testIsOther() {
		BasicFileAttributes attr = new CryptoBasicFileAttributes(delegateAttr, null, ciphertextFilePath, cryptor, Optional.empty(), false);
		Assert.assertFalse(attr.isRegularFile());
		Assert.assertFalse(attr.isDirectory());
		Assert.assertFalse(attr.isSymbolicLink());
		Assert.assertTrue(attr.isOther());
	}

	@Test
	public void testSizeOfFile() {
		Mockito.when(delegateAttr.size()).thenReturn(88l + 16 + 1337 + 32);
		BasicFileAttributes attr = new CryptoBasicFileAttributes(delegateAttr, FILE, ciphertextFilePath, cryptor, Optional.empty(), false);
		Assert.assertEquals(1337l, attr.size());
	}

	@Test
	public void testSizeOfOpenFile() {
		Mockito.when(delegateAttr.size()).thenReturn(42l);
		OpenCryptoFile openCryptoFile = Mockito.mock(OpenCryptoFile.class);
		Mockito.when(openCryptoFile.size()).thenReturn(1338l);
		BasicFileAttributes attr = new CryptoBasicFileAttributes(delegateAttr, FILE, ciphertextFilePath, cryptor, Optional.of(openCryptoFile), false);
		Assert.assertEquals(1338l, attr.size());
	}

	@Test
	public void testSizeOfDirectory() {
		Mockito.when(delegateAttr.size()).thenReturn(4096l);
		BasicFileAttributes attr = new CryptoBasicFileAttributes(delegateAttr, DIRECTORY, ciphertextFilePath, cryptor, Optional.empty(), false);
		Assert.assertEquals(4096l, attr.size());
	}

	@Test
	public void testSizeSetToZeroIfCryptoHeaderToSmall() {
		Mockito.when(delegateAttr.size()).thenReturn(88l + 20l);
		BasicFileAttributes attr = new CryptoBasicFileAttributes(delegateAttr, FILE, ciphertextFilePath, cryptor, Optional.empty(), false);
		Assert.assertEquals(attr.size(), 0);
	}

}
