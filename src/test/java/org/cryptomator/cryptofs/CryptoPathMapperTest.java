/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptofs;

import org.cryptomator.cryptofs.CryptoPathMapper.CiphertextFileType;
import org.cryptomator.cryptolib.api.Cryptor;
import org.cryptomator.cryptolib.api.FileNameCryptor;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentMatchers;
import org.mockito.Mockito;

import java.io.IOException;
import java.nio.file.FileSystem;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.spi.FileSystemProvider;

public class CryptoPathMapperTest {

	private final Path pathToVault = Mockito.mock(Path.class, "pathToVault");
	private final Path dataRoot = Mockito.mock(Path.class, "pathToVault/d/");
	private final Cryptor cryptor = Mockito.mock(Cryptor.class);
	private final FileNameCryptor fileNameCryptor = Mockito.mock(FileNameCryptor.class);
	private final DirectoryIdProvider dirIdProvider = Mockito.mock(DirectoryIdProvider.class);
	private final LongFileNameProvider longFileNameProvider = Mockito.mock(LongFileNameProvider.class);
	private final Symlinks symlinks = Mockito.mock(Symlinks.class);
	private final CryptoFileSystemImpl fileSystem = Mockito.mock(CryptoFileSystemImpl.class);

	@BeforeEach
	public void setup() {
		CryptoPathFactory cryptoPathFactory = new CryptoPathFactory(symlinks);
		CryptoPath root = cryptoPathFactory.rootFor(fileSystem);
		CryptoPath empty = cryptoPathFactory.emptyFor(fileSystem);
		Mockito.when(cryptor.fileNameCryptor()).thenReturn(fileNameCryptor);
		Mockito.when(pathToVault.resolve("d")).thenReturn(dataRoot);
		Mockito.when(fileSystem.getPath(ArgumentMatchers.anyString(), ArgumentMatchers.any())).thenAnswer(invocation -> {
			String first = invocation.getArgument(0);
			if (invocation.getArguments().length == 1) {
				return cryptoPathFactory.getPath(fileSystem, first);
			} else {
				String[] more = invocation.getArgument(1);
				return cryptoPathFactory.getPath(fileSystem, first, more);
			}
		});
		Mockito.when(fileSystem.getPathToVault()).thenReturn(pathToVault);
		Mockito.when(fileSystem.getRootPath()).thenReturn(root);
		Mockito.when(fileSystem.getEmptyPath()).thenReturn(empty);
	}

	@Test
	public void testPathEncryptionForRoot() throws IOException {
		Path d00 = Mockito.mock(Path.class);
		Mockito.when(dataRoot.resolve("00")).thenReturn(d00);
		Mockito.when(fileNameCryptor.hashDirectoryId("")).thenReturn("0000");

		Path d0000 = Mockito.mock(Path.class);
		Mockito.when(d00.resolve("00")).thenReturn(d0000);

		CryptoPathMapper mapper = new CryptoPathMapper(pathToVault, cryptor, dirIdProvider, longFileNameProvider);
		Path path = mapper.getCiphertextDir(fileSystem.getRootPath()).path;
		Assertions.assertEquals(d0000, path);
	}

	@Test
	public void testPathEncryptionForFoo() throws IOException {
		Path d00 = Mockito.mock(Path.class);
		Mockito.when(dataRoot.resolve("00")).thenReturn(d00);
		Mockito.when(fileNameCryptor.hashDirectoryId("")).thenReturn("0000");

		Path d0000 = Mockito.mock(Path.class, "d/00/00");
		Path d00000oof = Mockito.mock(Path.class, "d/00/00/0oof");
		Mockito.when(d00.resolve("00")).thenReturn(d0000);
		Mockito.when(d0000.resolve("0oof")).thenReturn(d00000oof);
		Mockito.when(fileNameCryptor.encryptFilename("foo", "".getBytes())).thenReturn("oof");
		Mockito.when(dirIdProvider.load(d00000oof)).thenReturn("1");
		Mockito.when(fileNameCryptor.hashDirectoryId("1")).thenReturn("0001");

		Path d0001 = Mockito.mock(Path.class);
		Mockito.when(d00.resolve("01")).thenReturn(d0001);

		CryptoPathMapper mapper = new CryptoPathMapper(pathToVault, cryptor, dirIdProvider, longFileNameProvider);
		Path path = mapper.getCiphertextDir(fileSystem.getPath("/foo")).path;
		Assertions.assertEquals(d0001, path);
	}

	@Test
	public void testPathEncryptionForFooBar() throws IOException {
		Path d00 = Mockito.mock(Path.class);
		Mockito.when(dataRoot.resolve("00")).thenReturn(d00);
		Mockito.when(fileNameCryptor.hashDirectoryId("")).thenReturn("0000");

		Path d0000 = Mockito.mock(Path.class, "d/00/00");
		Path d00000oof = Mockito.mock(Path.class, "d/00/00/0oof");
		Mockito.when(d00.resolve("00")).thenReturn(d0000);
		Mockito.when(d0000.resolve("0oof")).thenReturn(d00000oof);
		Mockito.when(fileNameCryptor.encryptFilename("foo", "".getBytes())).thenReturn("oof");
		Mockito.when(dirIdProvider.load(d00000oof)).thenReturn("1");
		Mockito.when(fileNameCryptor.hashDirectoryId("1")).thenReturn("0001");

		Path d0001 = Mockito.mock(Path.class, "d/00/01");
		Path d00010rab = Mockito.mock(Path.class, "d/00/01/0rab");
		Mockito.when(d00.resolve("01")).thenReturn(d0001);
		Mockito.when(d0001.resolve("0rab")).thenReturn(d00010rab);
		Mockito.when(fileNameCryptor.encryptFilename("bar", "1".getBytes())).thenReturn("rab");
		Mockito.when(dirIdProvider.load(d00010rab)).thenReturn("2");
		Mockito.when(fileNameCryptor.hashDirectoryId("2")).thenReturn("0002");

		Path d0002 = Mockito.mock(Path.class);
		Mockito.when(d00.resolve("02")).thenReturn(d0002);

		CryptoPathMapper mapper = new CryptoPathMapper(pathToVault, cryptor, dirIdProvider, longFileNameProvider);
		Path path = mapper.getCiphertextDir(fileSystem.getPath("/foo/bar")).path;
		Assertions.assertEquals(d0002, path);
	}

	@Test
	public void testPathEncryptionForFooBarBaz() throws IOException {
		Path d00 = Mockito.mock(Path.class, "d/00/");
		Mockito.when(dataRoot.resolve("00")).thenReturn(d00);
		Mockito.when(fileNameCryptor.hashDirectoryId("")).thenReturn("0000");

		Path d0000 = Mockito.mock(Path.class, "d/00/00");
		Path d00000oof = Mockito.mock(Path.class, "d/00/00/0oof");
		Mockito.when(d00.resolve("00")).thenReturn(d0000);
		Mockito.when(d0000.resolve("0oof")).thenReturn(d00000oof);
		Mockito.when(fileNameCryptor.encryptFilename("foo", "".getBytes())).thenReturn("oof");
		Mockito.when(dirIdProvider.load(d00000oof)).thenReturn("1");
		Mockito.when(fileNameCryptor.hashDirectoryId("1")).thenReturn("0001");

		Path d0001 = Mockito.mock(Path.class, "d/00/01");
		Path d00010rab = Mockito.mock(Path.class, "d/00/01/0rab");
		Mockito.when(d00.resolve("01")).thenReturn(d0001);
		Mockito.when(d0001.resolve("0rab")).thenReturn(d00010rab);
		Mockito.when(fileNameCryptor.encryptFilename("bar", "1".getBytes())).thenReturn("rab");
		Mockito.when(dirIdProvider.load(d00010rab)).thenReturn("2");
		Mockito.when(fileNameCryptor.hashDirectoryId("2")).thenReturn("0002");

		Path d0002 = Mockito.mock(Path.class, "d/00/02");
		Path d0002zab = Mockito.mock(Path.class, "d/00/02/zab");
		Path d00020zab = Mockito.mock(Path.class, "d/00/02/0zab");
		Mockito.when(d00.resolve("02")).thenReturn(d0002);
		Mockito.when(d0002.resolve("zab")).thenReturn(d0002zab);
		Mockito.when(d0002.resolve("0zab")).thenReturn(d00020zab);
		Mockito.when(fileNameCryptor.encryptFilename("baz", "2".getBytes())).thenReturn("zab");

		CryptoPathMapper mapper = new CryptoPathMapper(pathToVault, cryptor, dirIdProvider, longFileNameProvider);
		Path path = mapper.getCiphertextFilePath(fileSystem.getPath("/foo/bar/baz"), CiphertextFileType.FILE);
		Assertions.assertEquals(d0002zab, path);
		Path path2 = mapper.getCiphertextFilePath(fileSystem.getPath("/foo/bar/baz"), CiphertextFileType.DIRECTORY);
		Assertions.assertEquals(d00020zab, path2);
	}

	@Nested
	public class GetCiphertextFileType {

		private FileSystemProvider underlyingFileSystemProvider;
		private Path d0000CIPHER;
		private Path d00000CIPHER;
		private Path d00001SCIPHER;

		@BeforeEach
		public void setup() throws IOException {
			FileSystem underlyingFileSystem = Mockito.mock(FileSystem.class);
			underlyingFileSystemProvider = Mockito.mock(FileSystemProvider.class);
			Mockito.when(underlyingFileSystem.provider()).thenReturn(underlyingFileSystemProvider);

			Path d00 = Mockito.mock(Path.class);
			Path d0000 = Mockito.mock(Path.class, "d/00/00");
			Mockito.when(dataRoot.resolve("00")).thenReturn(d00);
			Mockito.when(d00.resolve("00")).thenReturn(d0000);
			Mockito.when(fileNameCryptor.hashDirectoryId("")).thenReturn("0000");

			Mockito.when(fileNameCryptor.encryptFilename("CLEAR", "".getBytes())).thenReturn("CIPHER");
			d0000CIPHER = Mockito.mock(Path.class, "d/00/00/CIPHER");
			d00000CIPHER = Mockito.mock(Path.class, "d/00/00/0CIPHER");
			d00001SCIPHER = Mockito.mock(Path.class, "d/00/00/1SCIPHER");
			Mockito.when(d0000.resolve("CIPHER")).thenReturn(d0000CIPHER);
			Mockito.when(d0000.resolve("0CIPHER")).thenReturn(d00000CIPHER);
			Mockito.when(d0000.resolve("1SCIPHER")).thenReturn(d00001SCIPHER);
			Mockito.when(d0000CIPHER.getFileSystem()).thenReturn(underlyingFileSystem);
			Mockito.when(d00000CIPHER.getFileSystem()).thenReturn(underlyingFileSystem);
			Mockito.when(d00001SCIPHER.getFileSystem()).thenReturn(underlyingFileSystem);
		}


		@Test
		public void testGetCiphertextFileTypeOfRootPath() throws IOException {
			CryptoPathMapper mapper = new CryptoPathMapper(pathToVault, cryptor, dirIdProvider, longFileNameProvider);
			CiphertextFileType type = mapper.getCiphertextFileType(fileSystem.getRootPath());
			Assertions.assertEquals(CiphertextFileType.DIRECTORY, type);
		}

		@Test
		public void testGetCiphertextFileTypeForNonexistingFile() throws IOException {
			Mockito.when(underlyingFileSystemProvider.readAttributes(d0000CIPHER, BasicFileAttributes.class)).thenThrow(NoSuchFileException.class);
			Mockito.when(underlyingFileSystemProvider.readAttributes(d00000CIPHER, BasicFileAttributes.class)).thenThrow(NoSuchFileException.class);
			Mockito.when(underlyingFileSystemProvider.readAttributes(d00001SCIPHER, BasicFileAttributes.class)).thenThrow(NoSuchFileException.class);

			CryptoPathMapper mapper = new CryptoPathMapper(pathToVault, cryptor, dirIdProvider, longFileNameProvider);

			CryptoPath path = fileSystem.getPath("/CLEAR");
			Assertions.assertThrows(NoSuchFileException.class, () -> {
				mapper.getCiphertextFileType(path);
			});
		}

		@Test
		public void testGetCiphertextFileTypeForFile() throws IOException {
			Mockito.when(underlyingFileSystemProvider.readAttributes(d0000CIPHER, BasicFileAttributes.class)).thenReturn(Mockito.mock(BasicFileAttributes.class));
			Mockito.when(underlyingFileSystemProvider.readAttributes(d00000CIPHER, BasicFileAttributes.class)).thenThrow(NoSuchFileException.class);
			Mockito.when(underlyingFileSystemProvider.readAttributes(d00001SCIPHER, BasicFileAttributes.class)).thenThrow(NoSuchFileException.class);

			CryptoPathMapper mapper = new CryptoPathMapper(pathToVault, cryptor, dirIdProvider, longFileNameProvider);

			CryptoPath path = fileSystem.getPath("/CLEAR");
			CiphertextFileType type = mapper.getCiphertextFileType(path);
			Assertions.assertEquals(CiphertextFileType.FILE, type);
		}

		@Test
		public void testGetCiphertextFileTypeForDirectory() throws IOException {
			Mockito.when(underlyingFileSystemProvider.readAttributes(d0000CIPHER, BasicFileAttributes.class)).thenThrow(NoSuchFileException.class);
			Mockito.when(underlyingFileSystemProvider.readAttributes(d00000CIPHER, BasicFileAttributes.class)).thenReturn(Mockito.mock(BasicFileAttributes.class));
			Mockito.when(underlyingFileSystemProvider.readAttributes(d00001SCIPHER, BasicFileAttributes.class)).thenThrow(NoSuchFileException.class);

			CryptoPathMapper mapper = new CryptoPathMapper(pathToVault, cryptor, dirIdProvider, longFileNameProvider);

			CryptoPath path = fileSystem.getPath("/CLEAR");
			CiphertextFileType type = mapper.getCiphertextFileType(path);
			Assertions.assertEquals(CiphertextFileType.DIRECTORY, type);
		}

		@Test
		public void testGetCiphertextFileTypeForSymlink() throws IOException {
			Mockito.when(underlyingFileSystemProvider.readAttributes(d0000CIPHER, BasicFileAttributes.class)).thenThrow(NoSuchFileException.class);
			Mockito.when(underlyingFileSystemProvider.readAttributes(d00000CIPHER, BasicFileAttributes.class)).thenThrow(NoSuchFileException.class);
			Mockito.when(underlyingFileSystemProvider.readAttributes(d00001SCIPHER, BasicFileAttributes.class)).thenReturn(Mockito.mock(BasicFileAttributes.class));

			CryptoPathMapper mapper = new CryptoPathMapper(pathToVault, cryptor, dirIdProvider, longFileNameProvider);

			CryptoPath path = fileSystem.getPath("/CLEAR");
			CiphertextFileType type = mapper.getCiphertextFileType(path);
			Assertions.assertEquals(CiphertextFileType.SYMLINK, type);
		}


	}

}
