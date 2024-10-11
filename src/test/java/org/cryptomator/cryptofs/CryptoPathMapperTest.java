/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptofs;

import com.google.common.base.Strings;
import org.cryptomator.cryptofs.common.CiphertextFileType;
import org.cryptomator.cryptolib.api.Cryptor;
import org.cryptomator.cryptolib.api.FileNameCryptor;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentMatchers;
import org.mockito.Mockito;

import java.io.IOException;
import java.nio.file.FileSystem;
import java.nio.file.LinkOption;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.spi.FileSystemProvider;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

public class CryptoPathMapperTest {

	private final Path pathToVault = Mockito.mock(Path.class, "pathToVault");
	private final Path dataRoot = Mockito.mock(Path.class, "pathToVault/d/");
	private final Cryptor cryptor = Mockito.mock(Cryptor.class);
	private final FileNameCryptor fileNameCryptor = Mockito.mock(FileNameCryptor.class);
	private final DirectoryIdProvider dirIdProvider = Mockito.mock(DirectoryIdProvider.class);
	private final LongFileNameProvider longFileNameProvider = Mockito.mock(LongFileNameProvider.class);
	private final VaultConfig vaultConfig = Mockito.mock(VaultConfig.class);
	private final Symlinks symlinks = Mockito.mock(Symlinks.class);
	private final CryptoFileSystemImpl fileSystem = Mockito.mock(CryptoFileSystemImpl.class);

	@BeforeEach
	public void setup() {
		CryptoPathFactory cryptoPathFactory = new CryptoPathFactory(symlinks);
		CryptoPath root = cryptoPathFactory.rootFor(fileSystem);
		CryptoPath empty = cryptoPathFactory.emptyFor(fileSystem);
		Mockito.when(cryptor.fileNameCryptor()).thenReturn(fileNameCryptor);
		Mockito.when(pathToVault.resolve("d")).thenReturn(dataRoot);
		Mockito.when(vaultConfig.getShorteningThreshold()).thenReturn(220);
		Mockito.when(fileSystem.getPath(ArgumentMatchers.anyString(), ArgumentMatchers.any(String[].class))).thenAnswer(invocation -> {
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
	@DisplayName("Removing a cached cleartext path also removes all cached child paths")
	public void testInvalidatingCleartextPathCleansCacheFromChildPaths() throws IOException {
		//prepare root
		Path d00 = Mockito.mock(Path.class);
		Mockito.when(dataRoot.resolve("00")).thenReturn(d00);
		Mockito.when(fileNameCryptor.hashDirectoryId("")).thenReturn("0000");

		//prepare cleartextDir "/foo"
		Path d0000 = Mockito.mock(Path.class, "d/00/00");
		Path d0000oof = Mockito.mock(Path.class, "d/00/00/oof.c9r");
		Path d0000oofdir = Mockito.mock(Path.class, "d/00/00/oof.c9r/dir.c9r");
		Mockito.when(d00.resolve("00")).thenReturn(d0000);
		Mockito.when(d0000.resolve("oof.c9r")).thenReturn(d0000oof);
		Mockito.when(d0000oof.resolve("dir.c9r")).thenReturn(d0000oofdir);
		Mockito.when(fileNameCryptor.encryptFilename(Mockito.any(), Mockito.eq("foo"), Mockito.any())).thenReturn("oof");
		Mockito.when(dirIdProvider.load(d0000oofdir)).thenReturn("1");
		Mockito.when(fileNameCryptor.hashDirectoryId("1")).thenReturn("0001");

		//prepare cleartextDir "/foo/bar"
		Path d0001 = Mockito.mock(Path.class, "d/00/01");
		Path d0001rab = Mockito.mock(Path.class, "d/00/01/rab.c9r");
		Path d0000rabdir = Mockito.mock(Path.class, "d/00/00/rab.c9r/dir.c9r");
		Mockito.when(d00.resolve("01")).thenReturn(d0001);
		Mockito.when(d0001.resolve("rab.c9r")).thenReturn(d0001rab);
		Mockito.when(d0001rab.resolve("dir.c9r")).thenReturn(d0000rabdir);
		Mockito.when(fileNameCryptor.encryptFilename(Mockito.any(), Mockito.eq("bar"), Mockito.any())).thenReturn("rab");
		Mockito.when(dirIdProvider.load(d0000rabdir)).thenReturn("2");
		Mockito.when(fileNameCryptor.hashDirectoryId("2")).thenReturn("0002");

		Path d0002 = Mockito.mock(Path.class);
		Mockito.when(d00.resolve("02")).thenReturn(d0002);

		CryptoPathMapper mapper = new CryptoPathMapper(pathToVault, cryptor, dirIdProvider, longFileNameProvider, vaultConfig);
		//put cleartextpath /foo
		Path cipherFooPath = mapper.getCiphertextDir(fileSystem.getPath("/foo")).path;
		//put cleartextpath /foo/bar
		Path cipherFooBarPath = mapper.getCiphertextDir(fileSystem.getPath("/foo/bar")).path;
		//invalidate /foo
		mapper.invalidatePathMapping(fileSystem.getPath("/foo"));
		//cache should miss
		var mapperSpy = Mockito.spy(mapper);
		mapperSpy.getCiphertextDir(fileSystem.getPath("/foo/bar"));
		Mockito.verify(mapperSpy, Mockito.atLeast(1)).getCiphertextFilePath(Mockito.any());
	}

	@Test
	@DisplayName("Moving a cached cleartext path also remaps all cached child paths")
	public void testMovingCleartextPathRemapsCachedChildPaths() throws IOException {
		CryptoPath fooPath = fileSystem.getPath("/foo");
		CryptoPath fooBarPath = fileSystem.getPath("/foo/bar");
		CryptoPath unkelFooPath = fileSystem.getPath("/unkel/foo");
		CryptoPath unkelFooBarPath = fileSystem.getPath("/unkel/foo/bar");
		//prepare root
		Path d00 = Mockito.mock(Path.class);
		Mockito.when(dataRoot.resolve("00")).thenReturn(d00);
		Mockito.when(fileNameCryptor.hashDirectoryId("")).thenReturn("0000");

		//prepare cleartextDir "/foo"
		Path d0000 = Mockito.mock(Path.class, "d/00/00");
		Path d0000oof = Mockito.mock(Path.class, "d/00/00/oof.c9r");
		Path d0000oofdir = Mockito.mock(Path.class, "d/00/00/oof.c9r/dir.c9r");
		Mockito.when(d00.resolve("00")).thenReturn(d0000);
		Mockito.when(d0000.resolve("oof.c9r")).thenReturn(d0000oof);
		Mockito.when(d0000oof.resolve("dir.c9r")).thenReturn(d0000oofdir);
		Mockito.when(fileNameCryptor.encryptFilename(Mockito.any(), Mockito.eq("foo"), Mockito.any())).thenReturn("oof");
		Mockito.when(dirIdProvider.load(d0000oofdir)).thenReturn("1");
		Mockito.when(fileNameCryptor.hashDirectoryId("1")).thenReturn("0001");

		//prepare cleartextDir "/foo/bar"
		Path d0001 = Mockito.mock(Path.class, "d/00/01");
		Path d0001rab = Mockito.mock(Path.class, "d/00/01/rab.c9r");
		Path d0000rabdir = Mockito.mock(Path.class, "d/00/00/rab.c9r/dir.c9r");
		Mockito.when(d00.resolve("01")).thenReturn(d0001);
		Mockito.when(d0001.resolve("rab.c9r")).thenReturn(d0001rab);
		Mockito.when(d0001rab.resolve("dir.c9r")).thenReturn(d0000rabdir);
		Mockito.when(fileNameCryptor.encryptFilename(Mockito.any(), Mockito.eq("bar"), Mockito.any())).thenReturn("rab");
		Mockito.when(dirIdProvider.load(d0000rabdir)).thenReturn("2");
		Mockito.when(fileNameCryptor.hashDirectoryId("2")).thenReturn("0002");

		Path d0002 = Mockito.mock(Path.class);
		Mockito.when(d00.resolve("02")).thenReturn(d0002);

		CryptoPathMapper mapper = new CryptoPathMapper(pathToVault, cryptor, dirIdProvider, longFileNameProvider, vaultConfig);
		//put cleartextpath /foo in cache
		Path cipherFooPath = mapper.getCiphertextDir(fooPath).path;
		//put cleartextpath /foo/bar in cache
		Path cipherBarPath = mapper.getCiphertextDir(fooBarPath).path;
		//move /foo to /unkel/dinkel/foo/, effectively moving also moving /foo/bar
		mapper.movePathMapping(fooPath, unkelFooPath);

		//cache should ...
		var mapperSpy = Mockito.spy(mapper);
		var someCiphertextFilePath = Mockito.mock(CiphertextFilePath.class);
		var someCiphertextDirFilePath = Mockito.mock(Path.class);
		var someCipherDirObj = Mockito.mock(CryptoPathMapper.CiphertextDirectory.class);
		Mockito.doReturn(someCiphertextFilePath).when(mapperSpy).getCiphertextFilePath(fooBarPath);
		Mockito.doReturn(someCiphertextDirFilePath).when(someCiphertextFilePath).getDirFilePath();
		Mockito.doReturn(someCipherDirObj).when(mapperSpy).resolveDirectory(someCiphertextDirFilePath);

		//... succeed for /unkel/foo/ and /unkel/foo/bar
		mapperSpy.getCiphertextDir(unkelFooPath);
		mapperSpy.getCiphertextDir(unkelFooBarPath);
		Mockito.verify(mapperSpy, Mockito.never()).getCiphertextFilePath(Mockito.any());

		//...miss and return our mocked cipherDirObj
		var actualCipherDirObj = mapperSpy.getCiphertextDir(fooBarPath);
		Assertions.assertEquals(someCipherDirObj, actualCipherDirObj);
	}

	@Test
	public void testPathEncryptionForRoot() throws IOException {
		Path d00 = Mockito.mock(Path.class);
		Mockito.when(dataRoot.resolve("00")).thenReturn(d00);
		Mockito.when(fileNameCryptor.hashDirectoryId("")).thenReturn("0000");

		Path d0000 = Mockito.mock(Path.class);
		Mockito.when(d00.resolve("00")).thenReturn(d0000);

		CryptoPathMapper mapper = new CryptoPathMapper(pathToVault, cryptor, dirIdProvider, longFileNameProvider, vaultConfig);
		Path path = mapper.getCiphertextDir(fileSystem.getRootPath()).path;
		Assertions.assertEquals(d0000, path);
	}

	@Test
	public void testPathEncryptionForFoo() throws IOException {
		Path d00 = Mockito.mock(Path.class);
		Mockito.when(dataRoot.resolve("00")).thenReturn(d00);
		Mockito.when(fileNameCryptor.hashDirectoryId("")).thenReturn("0000");

		Path d0000 = Mockito.mock(Path.class, "d/00/00");
		Path d0000oof = Mockito.mock(Path.class, "d/00/00/oof.c9r");
		Path d0000oofdir = Mockito.mock(Path.class, "d/00/00/oof.c9r/dir.c9r");
		Mockito.when(d00.resolve("00")).thenReturn(d0000);
		Mockito.when(d0000.resolve("oof.c9r")).thenReturn(d0000oof);
		Mockito.when(d0000oof.resolve("dir.c9r")).thenReturn(d0000oofdir);
		Mockito.when(fileNameCryptor.encryptFilename(Mockito.any(), Mockito.eq("foo"), Mockito.any())).thenReturn("oof");
		Mockito.when(dirIdProvider.load(d0000oofdir)).thenReturn("1");
		Mockito.when(fileNameCryptor.hashDirectoryId("1")).thenReturn("0001");

		Path d0001 = Mockito.mock(Path.class);
		Mockito.when(d00.resolve("01")).thenReturn(d0001);

		CryptoPathMapper mapper = new CryptoPathMapper(pathToVault, cryptor, dirIdProvider, longFileNameProvider, vaultConfig);
		Path path = mapper.getCiphertextDir(fileSystem.getPath("/foo")).path;
		Assertions.assertEquals(d0001, path);
	}

	@Test
	public void testPathEncryptionForFooBar() throws IOException {
		Path d00 = Mockito.mock(Path.class);
		Mockito.when(dataRoot.resolve("00")).thenReturn(d00);
		Mockito.when(fileNameCryptor.hashDirectoryId("")).thenReturn("0000");

		Path d0000 = Mockito.mock(Path.class, "d/00/00");
		Path d0000oof = Mockito.mock(Path.class, "d/00/00/oof.c9r");
		Path d0000oofdir = Mockito.mock(Path.class, "d/00/00/oof.c9r/dir.c9r");
		Mockito.when(d00.resolve("00")).thenReturn(d0000);
		Mockito.when(d0000.resolve("oof.c9r")).thenReturn(d0000oof);
		Mockito.when(d0000oof.resolve("dir.c9r")).thenReturn(d0000oofdir);
		Mockito.when(fileNameCryptor.encryptFilename(Mockito.any(), Mockito.eq("foo"), Mockito.any())).thenReturn("oof");
		Mockito.when(dirIdProvider.load(d0000oofdir)).thenReturn("1");
		Mockito.when(fileNameCryptor.hashDirectoryId("1")).thenReturn("0001");

		Path d0001 = Mockito.mock(Path.class, "d/00/01");
		Path d0001rab = Mockito.mock(Path.class, "d/00/01/rab.c9r");
		Path d0000rabdir = Mockito.mock(Path.class, "d/00/00/rab.c9r/dir.c9r");
		Mockito.when(d00.resolve("01")).thenReturn(d0001);
		Mockito.when(d0001.resolve("rab.c9r")).thenReturn(d0001rab);
		Mockito.when(d0001rab.resolve("dir.c9r")).thenReturn(d0000rabdir);
		Mockito.when(fileNameCryptor.encryptFilename(Mockito.any(), Mockito.eq("bar"), Mockito.any())).thenReturn("rab");
		Mockito.when(dirIdProvider.load(d0000rabdir)).thenReturn("2");
		Mockito.when(fileNameCryptor.hashDirectoryId("2")).thenReturn("0002");

		Path d0002 = Mockito.mock(Path.class);
		Mockito.when(d00.resolve("02")).thenReturn(d0002);

		CryptoPathMapper mapper = new CryptoPathMapper(pathToVault, cryptor, dirIdProvider, longFileNameProvider, vaultConfig);
		Path path = mapper.getCiphertextDir(fileSystem.getPath("/foo/bar")).path;
		Assertions.assertEquals(d0002, path);
	}

	@DisplayName("Decrypts a deeply nested filepath")
	@Test
	public void testPathEncryptionDEEP() throws IOException {
		Path d00 = Mockito.mock(Path.class, "d/00/");
		Mockito.when(dataRoot.resolve("00")).thenReturn(d00);
		Mockito.when(fileNameCryptor.hashDirectoryId("")).thenReturn("0000");

		int maxNestingDepth = 97;

		for (int depth = 0; depth < maxNestingDepth; depth++) {
			var dirId = "%02d".formatted(depth);
			var nextDirId = "%02d".formatted(depth + 1);
			String pathPrefix = "d/00/" + dirId;
			Path contentDir = Mockito.mock(Path.class, pathPrefix);
			Path dirLinkDir = Mockito.mock(Path.class, pathPrefix + "/cipherDir" + dirId + ".c9r");
			Path dirLinkFile = Mockito.mock(Path.class, pathPrefix + "/cipherDir" + dirId + ".c9r/dir.c9r");
			Mockito.when(d00.resolve(dirId)).thenReturn(contentDir);
			Mockito.when(contentDir.resolve("cipherDir" + dirId + ".c9r")).thenReturn(dirLinkDir);
			Mockito.when(dirLinkDir.resolve("dir.c9r")).thenReturn(dirLinkFile);
			Mockito.when(fileNameCryptor.encryptFilename(Mockito.any(), Mockito.eq(dirId), Mockito.any())).thenReturn("cipherDir" + dirId);
			Mockito.when(dirIdProvider.load(dirLinkFile)).thenReturn(nextDirId);
			Mockito.when(fileNameCryptor.hashDirectoryId(nextDirId)).thenReturn("%04d".formatted(depth + 1));
		}

		var finalDirId = "%02d".formatted(maxNestingDepth);
		Path finalContentDir = Mockito.mock(Path.class, "d/00/" + finalDirId);
		Path finalEncryptedFile = Mockito.mock(Path.class, "d/00/" + finalDirId + "/file.c9r");
		Mockito.when(d00.resolve(finalDirId)).thenReturn(finalContentDir);
		Mockito.when(finalContentDir.resolve("file.c9r")).thenReturn(finalEncryptedFile);
		Mockito.when(fileNameCryptor.encryptFilename(Mockito.any(), Mockito.eq("cleartextFile"), Mockito.any())).thenReturn("file");

		var testPath = "/" + IntStream.range(0, maxNestingDepth).mapToObj("%02d"::formatted).collect(Collectors.joining("/")) + "/cleartextFile";

		CryptoPathMapper mapper = new CryptoPathMapper(pathToVault, cryptor, dirIdProvider, longFileNameProvider, vaultConfig);
		Path path = mapper.getCiphertextFilePath(fileSystem.getPath(testPath)).getRawPath();
		Assertions.assertEquals(finalEncryptedFile, path);
	}

	@Test
	public void testPathEncryptionForFooBarBaz() throws IOException {
		Path d00 = Mockito.mock(Path.class, "d/00/");
		Mockito.when(dataRoot.resolve("00")).thenReturn(d00);
		Mockito.when(fileNameCryptor.hashDirectoryId("")).thenReturn("0000");

		Path d0000 = Mockito.mock(Path.class, "d/00/00");
		Path d0000oof = Mockito.mock(Path.class, "d/00/00/oof.c9r");
		Path d0000oofdir = Mockito.mock(Path.class, "d/00/00/oof.c9r/dir.c9r");
		Mockito.when(d00.resolve("00")).thenReturn(d0000);
		Mockito.when(d0000.resolve("oof.c9r")).thenReturn(d0000oof);
		Mockito.when(d0000oof.resolve("dir.c9r")).thenReturn(d0000oofdir);
		Mockito.when(fileNameCryptor.encryptFilename(Mockito.any(), Mockito.eq("foo"), Mockito.any())).thenReturn("oof");
		Mockito.when(dirIdProvider.load(d0000oofdir)).thenReturn("1");
		Mockito.when(fileNameCryptor.hashDirectoryId("1")).thenReturn("0001");

		Path d0001 = Mockito.mock(Path.class, "d/00/01");
		Path d0001rab = Mockito.mock(Path.class, "d/00/01/rab.c9r");
		Path d0000rabdir = Mockito.mock(Path.class, "d/00/00/rab.c9r/dir.c9r");
		Mockito.when(d00.resolve("01")).thenReturn(d0001);
		Mockito.when(d0001.resolve("rab.c9r")).thenReturn(d0001rab);
		Mockito.when(d0001rab.resolve("dir.c9r")).thenReturn(d0000rabdir);
		Mockito.when(fileNameCryptor.encryptFilename(Mockito.any(), Mockito.eq("bar"), Mockito.any())).thenReturn("rab");
		Mockito.when(dirIdProvider.load(d0000rabdir)).thenReturn("2");
		Mockito.when(fileNameCryptor.hashDirectoryId("2")).thenReturn("0002");

		Path d0002 = Mockito.mock(Path.class, "d/00/02");
		Path d0002zab = Mockito.mock(Path.class, "d/00/02/zab.c9r");
		Mockito.when(d00.resolve("02")).thenReturn(d0002);
		Mockito.when(d0002.resolve("zab.c9r")).thenReturn(d0002zab);
		Mockito.when(fileNameCryptor.encryptFilename(Mockito.any(), Mockito.eq("baz"), Mockito.any())).thenReturn("zab");

		CryptoPathMapper mapper = new CryptoPathMapper(pathToVault, cryptor, dirIdProvider, longFileNameProvider, vaultConfig);
		Path path = mapper.getCiphertextFilePath(fileSystem.getPath("/foo/bar/baz")).getRawPath();
		Assertions.assertEquals(d0002zab, path);
	}

	@Nested
	public class GetCiphertextFileType {

		private FileSystemProvider underlyingFileSystemProvider;
		private Path c9rPath;
		private Path dirFilePath;
		private Path symlinkFilePath;
		private Path contentsFilePath;
		private BasicFileAttributes c9rAttrs;

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

			Mockito.when(fileNameCryptor.encryptFilename(Mockito.any(), Mockito.eq("CLEAR"), Mockito.any())).thenReturn("CIPHER");
			c9rPath = Mockito.mock(Path.class, "d/00/00/CIPHER.c9r");
			c9rAttrs = Mockito.mock(BasicFileAttributes.class, "attributes for d/00/00/CIPHER.c9r");
			Mockito.when(d0000.resolve("CIPHER.c9r")).thenReturn(c9rPath);
			Mockito.when(c9rPath.getFileSystem()).thenReturn(underlyingFileSystem);

			dirFilePath = Mockito.mock(Path.class, "d/00/00/CIPHER.c9r/dir.c9r");
			symlinkFilePath = Mockito.mock(Path.class, "d/00/00/CIPHER.c9r/symlink.c9r");
			contentsFilePath = Mockito.mock(Path.class, "d/00/00/CIPHER.c9r/contents.c9r");
			Mockito.when(c9rPath.resolve("dir.c9r")).thenReturn(dirFilePath);
			Mockito.when(c9rPath.resolve("symlink.c9r")).thenReturn(symlinkFilePath);
			Mockito.when(c9rPath.resolve("contents.c9r")).thenReturn(contentsFilePath);
			Mockito.when(dirFilePath.getFileSystem()).thenReturn(underlyingFileSystem);
			Mockito.when(symlinkFilePath.getFileSystem()).thenReturn(underlyingFileSystem);
			Mockito.when(contentsFilePath.getFileSystem()).thenReturn(underlyingFileSystem);

		}


		@Test
		public void testGetCiphertextFileTypeOfRootPath() throws IOException {
			CryptoPathMapper mapper = new CryptoPathMapper(pathToVault, cryptor, dirIdProvider, longFileNameProvider, vaultConfig);
			CiphertextFileType type = mapper.getCiphertextFileType(fileSystem.getRootPath());
			Assertions.assertEquals(CiphertextFileType.DIRECTORY, type);
		}

		@Test
		public void testGetCiphertextFileTypeForNonexistingFile() throws IOException {
			Mockito.when(underlyingFileSystemProvider.readAttributes(c9rPath, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS)).thenThrow(NoSuchFileException.class);

			CryptoPathMapper mapper = new CryptoPathMapper(pathToVault, cryptor, dirIdProvider, longFileNameProvider, vaultConfig);

			CryptoPath path = fileSystem.getPath("/CLEAR");
			Assertions.assertThrows(NoSuchFileException.class, () -> {
				mapper.getCiphertextFileType(path);
			});
		}

		@Test
		public void testGetCiphertextFileTypeForFile() throws IOException {
			Mockito.when(underlyingFileSystemProvider.readAttributes(c9rPath, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS)).thenReturn(c9rAttrs);
			Mockito.when(c9rAttrs.isDirectory()).thenReturn(false);

			CryptoPathMapper mapper = new CryptoPathMapper(pathToVault, cryptor, dirIdProvider, longFileNameProvider, vaultConfig);

			CryptoPath path = fileSystem.getPath("/CLEAR");
			CiphertextFileType type = mapper.getCiphertextFileType(path);
			Assertions.assertEquals(CiphertextFileType.FILE, type);
		}

		@Test
		public void testGetCiphertextFileTypeForDirectory() throws IOException {
			Mockito.when(underlyingFileSystemProvider.readAttributes(c9rPath, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS)).thenReturn(c9rAttrs);
			Mockito.when(c9rAttrs.isDirectory()).thenReturn(true);
			Mockito.when(underlyingFileSystemProvider.readAttributes(dirFilePath, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS)).thenReturn(Mockito.mock(BasicFileAttributes.class));
			Mockito.when(underlyingFileSystemProvider.readAttributes(symlinkFilePath, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS)).thenThrow(NoSuchFileException.class);
			Mockito.when(underlyingFileSystemProvider.readAttributes(contentsFilePath, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS)).thenThrow(NoSuchFileException.class);
			Mockito.when(underlyingFileSystemProvider.exists(dirFilePath, LinkOption.NOFOLLOW_LINKS)).thenReturn(true);

			CryptoPathMapper mapper = new CryptoPathMapper(pathToVault, cryptor, dirIdProvider, longFileNameProvider, vaultConfig);

			CryptoPath path = fileSystem.getPath("/CLEAR");
			CiphertextFileType type = mapper.getCiphertextFileType(path);
			Assertions.assertEquals(CiphertextFileType.DIRECTORY, type);
		}

		@Test
		public void testGetCiphertextFileTypeForSymlink() throws IOException {
			Mockito.when(underlyingFileSystemProvider.readAttributes(c9rPath, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS)).thenReturn(c9rAttrs);
			Mockito.when(c9rAttrs.isDirectory()).thenReturn(true);
			Mockito.when(underlyingFileSystemProvider.readAttributes(dirFilePath, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS)).thenThrow(NoSuchFileException.class);
			Mockito.when(underlyingFileSystemProvider.readAttributes(symlinkFilePath, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS)).thenReturn(Mockito.mock(BasicFileAttributes.class));
			Mockito.when(underlyingFileSystemProvider.readAttributes(contentsFilePath, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS)).thenThrow(NoSuchFileException.class);
			Mockito.when(underlyingFileSystemProvider.exists(symlinkFilePath, LinkOption.NOFOLLOW_LINKS)).thenReturn(true);

			CryptoPathMapper mapper = new CryptoPathMapper(pathToVault, cryptor, dirIdProvider, longFileNameProvider, vaultConfig);

			CryptoPath path = fileSystem.getPath("/CLEAR");
			CiphertextFileType type = mapper.getCiphertextFileType(path);
			Assertions.assertEquals(CiphertextFileType.SYMLINK, type);
		}

		@Test
		public void testGetCiphertextFileTypeForShortenedFile() throws IOException {
			Mockito.when(underlyingFileSystemProvider.readAttributes(c9rPath, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS)).thenReturn(c9rAttrs);
			Mockito.when(c9rAttrs.isDirectory()).thenReturn(true);
			Mockito.when(underlyingFileSystemProvider.readAttributes(dirFilePath, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS)).thenThrow(NoSuchFileException.class);
			Mockito.when(underlyingFileSystemProvider.readAttributes(symlinkFilePath, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS)).thenThrow(NoSuchFileException.class);
			Mockito.when(underlyingFileSystemProvider.readAttributes(contentsFilePath, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS)).thenReturn(Mockito.mock(BasicFileAttributes.class));
			Mockito.when(fileNameCryptor.encryptFilename(Mockito.any(), Mockito.eq("LONGCLEAR"), Mockito.any())).thenReturn(Strings.repeat("A", 1000));
			Mockito.when(longFileNameProvider.deflate(Mockito.any())).thenReturn(new LongFileNameProvider.DeflatedFileName(c9rPath, null, null));
			Mockito.when(underlyingFileSystemProvider.exists(contentsFilePath, LinkOption.NOFOLLOW_LINKS)).thenReturn(true);

			CryptoPathMapper mapper = new CryptoPathMapper(pathToVault, cryptor, dirIdProvider, longFileNameProvider, vaultConfig);

			CryptoPath path = fileSystem.getPath("/LONGCLEAR");
			CiphertextFileType type = mapper.getCiphertextFileType(path);
			Assertions.assertEquals(CiphertextFileType.FILE, type);
		}


	}

}
