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
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import org.cryptomator.cryptofs.CryptoPathMapper.CiphertextFileType;
import org.cryptomator.cryptolib.api.Cryptor;
import org.cryptomator.cryptolib.api.FileNameCryptor;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;

public class CryptoPathMapperTest {

	private Path tmpPath;
	private Cryptor cryptor;
	private FileNameCryptor nameCryptor;
	private DirectoryIdProvider dirIdProvider;
	private LongFileNameProvider longFileNameProvider;

	@Before
	public void setup() throws IOException {
		tmpPath = Files.createTempDirectory("unit-tests");
		cryptor = Mockito.mock(Cryptor.class);
		nameCryptor = Mockito.mock(FileNameCryptor.class);
		Mockito.when(cryptor.fileNameCryptor()).thenReturn(nameCryptor);
		dirIdProvider = Mockito.mock(DirectoryIdProvider.class);
		longFileNameProvider = Mockito.mock(LongFileNameProvider.class);
	}

	@After
	public void teardown() throws IOException {
		Files.delete(tmpPath);
	}

	@Test
	public void testPathEncryptionForRoot() throws IOException {
		Mockito.when(nameCryptor.hashDirectoryId("")).thenReturn("0000");

		CryptoPathMapper mapper = new CryptoPathMapper(tmpPath, cryptor, dirIdProvider, longFileNameProvider);
		Path path = mapper.getCiphertextDirPath(Paths.get("/"));
		Assert.assertEquals(tmpPath.resolve("d/00/00"), path);
	}

	@Test
	public void testPathEncryptionForFoo() throws IOException {
		Mockito.when(nameCryptor.hashDirectoryId("")).thenReturn("0000");

		Mockito.when(nameCryptor.encryptFilename("foo", "".getBytes())).thenReturn("oof");
		Mockito.when(dirIdProvider.load(tmpPath.resolve("d/00/00/0oof"))).thenReturn("1");
		Mockito.when(nameCryptor.hashDirectoryId("1")).thenReturn("0001");

		CryptoPathMapper mapper = new CryptoPathMapper(tmpPath, cryptor, dirIdProvider, longFileNameProvider);
		Path path = mapper.getCiphertextDirPath(Paths.get("/foo"));
		Assert.assertEquals(tmpPath.resolve("d/00/01/"), path);
	}

	@Test
	public void testPathEncryptionForFooBar() throws IOException {
		Mockito.when(nameCryptor.hashDirectoryId("")).thenReturn("0000");

		Mockito.when(nameCryptor.encryptFilename("foo", "".getBytes())).thenReturn("oof");
		Mockito.when(dirIdProvider.load(tmpPath.resolve("d/00/00/0oof"))).thenReturn("1");
		Mockito.when(nameCryptor.hashDirectoryId("1")).thenReturn("0001");

		Mockito.when(nameCryptor.encryptFilename("bar", "1".getBytes())).thenReturn("rab");
		Mockito.when(dirIdProvider.load(tmpPath.resolve("d/00/01/0rab"))).thenReturn("2");
		Mockito.when(nameCryptor.hashDirectoryId("2")).thenReturn("0002");

		CryptoPathMapper mapper = new CryptoPathMapper(tmpPath, cryptor, dirIdProvider, longFileNameProvider);
		Path path = mapper.getCiphertextDirPath(Paths.get("/foo/bar"));
		Assert.assertEquals(tmpPath.resolve("d/00/02/"), path);
	}

	@Test
	public void testPathEncryptionForFooBarBaz() throws IOException {
		Mockito.when(nameCryptor.hashDirectoryId("")).thenReturn("0000");

		Mockito.when(nameCryptor.encryptFilename("foo", "".getBytes())).thenReturn("oof");
		Mockito.when(dirIdProvider.load(tmpPath.resolve("d/00/00/0oof"))).thenReturn("1");
		Mockito.when(nameCryptor.hashDirectoryId("1")).thenReturn("0001");

		Mockito.when(nameCryptor.encryptFilename("bar", "1".getBytes())).thenReturn("rab");
		Mockito.when(dirIdProvider.load(tmpPath.resolve("d/00/01/0rab"))).thenReturn("2");
		Mockito.when(nameCryptor.hashDirectoryId("2")).thenReturn("0002");

		Mockito.when(nameCryptor.encryptFilename("baz", "2".getBytes())).thenReturn("zab");

		CryptoPathMapper mapper = new CryptoPathMapper(tmpPath, cryptor, dirIdProvider, longFileNameProvider);
		Path path = mapper.getCiphertextFilePath(Paths.get("/foo/bar/baz"), CiphertextFileType.FILE);
		Assert.assertEquals(tmpPath.resolve("d/00/02/zab"), path);

		Path path2 = mapper.getCiphertextFilePath(Paths.get("/foo/bar/baz"), CiphertextFileType.DIRECTORY);
		Assert.assertEquals(tmpPath.resolve("d/00/02/0zab"), path2);
	}

}
