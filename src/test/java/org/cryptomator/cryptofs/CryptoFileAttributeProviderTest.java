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
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.DosFileAttributes;
import java.nio.file.attribute.PosixFileAttributes;
import java.nio.file.spi.FileSystemProvider;

import org.cryptomator.cryptolib.api.Cryptor;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;

public class CryptoFileAttributeProviderTest {

	private Cryptor cryptor;
	private CryptoPathMapper pathMapper;
	private OpenCryptoFiles openCryptoFiles;
	private CryptoFileSystemProperties fileSystemProperties;
	private CryptoPath cleartextPath;
	private Path ciphertextFilePath;

	@Before
	public void setup() throws IOException {
		cryptor = Mockito.mock(Cryptor.class);
		pathMapper = Mockito.mock(CryptoPathMapper.class);
		openCryptoFiles = Mockito.mock(OpenCryptoFiles.class);
		fileSystemProperties = Mockito.mock(CryptoFileSystemProperties.class);
		cleartextPath = Mockito.mock(CryptoPath.class, "cleartextPath");
		ciphertextFilePath = Mockito.mock(Path.class, "ciphertextPath");
		FileSystem fs = Mockito.mock(FileSystem.class);
		Mockito.when(ciphertextFilePath.getFileSystem()).thenReturn(fs);
		FileSystemProvider provider = Mockito.mock(FileSystemProvider.class);
		Mockito.when(fs.provider()).thenReturn(provider);
		BasicFileAttributes basicAttr = Mockito.mock(BasicFileAttributes.class);
		PosixFileAttributes posixAttr = Mockito.mock(PosixFileAttributes.class);
		DosFileAttributes dosAttr = Mockito.mock(DosFileAttributes.class);
		Mockito.when(provider.readAttributes(Mockito.same(ciphertextFilePath), Mockito.same(BasicFileAttributes.class), Mockito.any())).thenReturn(basicAttr);
		Mockito.when(provider.readAttributes(Mockito.same(ciphertextFilePath), Mockito.same(PosixFileAttributes.class), Mockito.any())).thenReturn(posixAttr);
		Mockito.when(provider.readAttributes(Mockito.same(ciphertextFilePath), Mockito.same(DosFileAttributes.class), Mockito.any())).thenReturn(dosAttr);

		Mockito.when(pathMapper.getCiphertextFileType(cleartextPath)).thenReturn(CryptoPathMapper.CiphertextFileType.FILE);
		Mockito.when(pathMapper.getCiphertextFilePath(cleartextPath, CryptoPathMapper.CiphertextFileType.FILE)).thenReturn(ciphertextFilePath);
	}

	@Test
	public void testReadBasicAttributes() throws IOException {
		CryptoFileAttributeProvider prov = new CryptoFileAttributeProvider(cryptor, pathMapper, openCryptoFiles, fileSystemProperties);
		BasicFileAttributes attr = prov.readAttributes(cleartextPath, BasicFileAttributes.class);
		Assert.assertTrue(attr instanceof BasicFileAttributes);
	}

	@Test
	public void testReadPosixAttributes() throws IOException {
		CryptoFileAttributeProvider prov = new CryptoFileAttributeProvider(cryptor, pathMapper, openCryptoFiles, fileSystemProperties);
		PosixFileAttributes attr = prov.readAttributes(cleartextPath, PosixFileAttributes.class);
		Assert.assertTrue(attr instanceof PosixFileAttributes);
	}

	@Test
	public void testReadDosAttributes() throws IOException {
		CryptoFileAttributeProvider prov = new CryptoFileAttributeProvider(cryptor, pathMapper, openCryptoFiles, fileSystemProperties);
		DosFileAttributes attr = prov.readAttributes(cleartextPath, DosFileAttributes.class);
		Assert.assertTrue(attr instanceof DosFileAttributes);
	}

	@Test(expected = UnsupportedOperationException.class)
	public void testReadUnsupportedAttributes() throws IOException {
		CryptoFileAttributeProvider prov = new CryptoFileAttributeProvider(cryptor, pathMapper, openCryptoFiles, fileSystemProperties);
		prov.readAttributes(cleartextPath, UnsupportedAttributes.class);
	}

	private interface UnsupportedAttributes extends BasicFileAttributes {

	}

}
