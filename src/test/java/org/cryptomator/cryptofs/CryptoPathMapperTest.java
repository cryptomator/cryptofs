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
import java.nio.file.Path;

import org.cryptomator.cryptofs.CryptoPathMapper.CiphertextFileType;
import org.cryptomator.cryptolib.api.Cryptor;
import org.cryptomator.cryptolib.api.FileNameCryptor;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;

public class CryptoPathMapperTest {

	private final Path pathToVault = Mockito.mock(Path.class, "pathToVault");
	private final Path dataRoot = Mockito.mock(Path.class, "pathToVault/d/");
	private final Cryptor cryptor = Mockito.mock(Cryptor.class);
	private final FileNameCryptor fileNameCryptor = Mockito.mock(FileNameCryptor.class);
	private final DirectoryIdProvider dirIdProvider = Mockito.mock(DirectoryIdProvider.class);
	private final LongFileNameProvider longFileNameProvider = Mockito.mock(LongFileNameProvider.class);
	private final CryptoFileSystemImpl fileSystem = Mockito.mock(CryptoFileSystemImpl.class);

	@Before
	public void setup() throws IOException {
		Mockito.when(cryptor.fileNameCryptor()).thenReturn(fileNameCryptor);
		Mockito.when(pathToVault.resolve("d")).thenReturn(dataRoot);
		TestHelper.prepareMockForPathCreation(fileSystem, pathToVault);
	}

	@Test
	public void testPathEncryptionForRoot() throws IOException {
		Path d00 = Mockito.mock(Path.class);
		Mockito.when(dataRoot.resolve("00")).thenReturn(d00);
		Mockito.when(fileNameCryptor.hashDirectoryId("")).thenReturn("0000");

		Path d0000 = Mockito.mock(Path.class);
		Mockito.when(d00.resolve("00")).thenReturn(d0000);

		CryptoPathMapper mapper = new CryptoPathMapper(pathToVault, cryptor, dirIdProvider, longFileNameProvider);
		Path path = mapper.getCiphertextDirPath(fileSystem.getRootPath());
		Assert.assertEquals(d0000, path);
	}

	@Test
	public void testPathEncryptionForFoo() throws IOException {
		Path d00 = Mockito.mock(Path.class);
		Mockito.when(dataRoot.resolve("00")).thenReturn(d00);
		Mockito.when(fileNameCryptor.hashDirectoryId("")).thenReturn("0000");

		Path d0000 = Mockito.mock(Path.class);
		Mockito.when(d00.resolve("00")).thenReturn(d0000);
		Mockito.when(fileNameCryptor.encryptFilename("foo", "".getBytes())).thenReturn("oof");
		Mockito.when(dirIdProvider.load(pathToVault.resolve("d/00/00/0oof"))).thenReturn("1");
		Mockito.when(fileNameCryptor.hashDirectoryId("1")).thenReturn("0001");

		Path d0001 = Mockito.mock(Path.class);
		Mockito.when(d00.resolve("01")).thenReturn(d0001);

		CryptoPathMapper mapper = new CryptoPathMapper(pathToVault, cryptor, dirIdProvider, longFileNameProvider);
		Path path = mapper.getCiphertextDirPath(fileSystem.getPath("/foo"));
		Assert.assertEquals(d0001, path);
	}

	@Test
	public void testPathEncryptionForFooBar() throws IOException {
		Path d00 = Mockito.mock(Path.class);
		Mockito.when(dataRoot.resolve("00")).thenReturn(d00);
		Mockito.when(fileNameCryptor.hashDirectoryId("")).thenReturn("0000");

		Path d0000 = Mockito.mock(Path.class);
		Mockito.when(d00.resolve("00")).thenReturn(d0000);
		Mockito.when(fileNameCryptor.encryptFilename("foo", "".getBytes())).thenReturn("oof");
		Mockito.when(dirIdProvider.load(pathToVault.resolve("d/00/00/0oof"))).thenReturn("1");
		Mockito.when(fileNameCryptor.hashDirectoryId("1")).thenReturn("0001");

		Path d0001 = Mockito.mock(Path.class);
		Mockito.when(d00.resolve("01")).thenReturn(d0001);
		Mockito.when(fileNameCryptor.encryptFilename("bar", "1".getBytes())).thenReturn("rab");
		Mockito.when(dirIdProvider.load(pathToVault.resolve("d/00/01/0rab"))).thenReturn("2");
		Mockito.when(fileNameCryptor.hashDirectoryId("2")).thenReturn("0002");

		Path d0002 = Mockito.mock(Path.class);
		Mockito.when(d00.resolve("02")).thenReturn(d0002);

		CryptoPathMapper mapper = new CryptoPathMapper(pathToVault, cryptor, dirIdProvider, longFileNameProvider);
		Path path = mapper.getCiphertextDirPath(fileSystem.getPath("/foo/bar"));
		Assert.assertEquals(d0002, path);
	}

	@Test
	public void testPathEncryptionForFooBarBaz() throws IOException {
		Path d00 = Mockito.mock(Path.class);
		Mockito.when(dataRoot.resolve("00")).thenReturn(d00);
		Mockito.when(fileNameCryptor.hashDirectoryId("")).thenReturn("0000");

		Path d0000 = Mockito.mock(Path.class);
		Mockito.when(d00.resolve("00")).thenReturn(d0000);
		Mockito.when(fileNameCryptor.encryptFilename("foo", "".getBytes())).thenReturn("oof");
		Mockito.when(dirIdProvider.load(pathToVault.resolve("d/00/00/0oof"))).thenReturn("1");
		Mockito.when(fileNameCryptor.hashDirectoryId("1")).thenReturn("0001");

		Path d0001 = Mockito.mock(Path.class);
		Mockito.when(d00.resolve("01")).thenReturn(d0001);
		Mockito.when(fileNameCryptor.encryptFilename("bar", "1".getBytes())).thenReturn("rab");
		Mockito.when(dirIdProvider.load(pathToVault.resolve("d/00/01/0rab"))).thenReturn("2");
		Mockito.when(fileNameCryptor.hashDirectoryId("2")).thenReturn("0002");

		Path d0002 = Mockito.mock(Path.class);
		Mockito.when(d00.resolve("02")).thenReturn(d0002);
		Mockito.when(fileNameCryptor.encryptFilename("baz", "2".getBytes())).thenReturn("zab");

		Path d0002zab = Mockito.mock(Path.class);
		Path d00020zab = Mockito.mock(Path.class);
		Mockito.when(d0002.resolve("zab")).thenReturn(d0002zab);
		Mockito.when(d0002.resolve("0zab")).thenReturn(d00020zab);

		CryptoPathMapper mapper = new CryptoPathMapper(pathToVault, cryptor, dirIdProvider, longFileNameProvider);
		Path path = mapper.getCiphertextFilePath(fileSystem.getPath("/foo/bar/baz"), CiphertextFileType.FILE);
		Assert.assertEquals(d0002zab, path);
		Path path2 = mapper.getCiphertextFilePath(fileSystem.getPath("/foo/bar/baz"), CiphertextFileType.DIRECTORY);
		Assert.assertEquals(d00020zab, path2);
	}

}
