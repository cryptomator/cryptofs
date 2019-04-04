/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptofs.attr;

import org.cryptomator.cryptofs.CryptoFileSystemProperties;
import org.cryptomator.cryptofs.CryptoPath;
import org.cryptomator.cryptofs.CryptoPathMapper;
import org.cryptomator.cryptofs.CryptoPathMapper.CiphertextDirectory;
import org.cryptomator.cryptofs.fh.OpenCryptoFiles;
import org.cryptomator.cryptofs.Symlinks;
import org.cryptomator.cryptolib.api.Cryptor;
import org.cryptomator.cryptolib.api.FileContentCryptor;
import org.cryptomator.cryptolib.api.FileHeaderCryptor;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.io.IOException;
import java.nio.file.FileSystem;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.DosFileAttributes;
import java.nio.file.attribute.PosixFileAttributes;
import java.nio.file.spi.FileSystemProvider;

public class AttributeProviderTest {

	private Cryptor cryptor;
	private CryptoPathMapper pathMapper;
	private OpenCryptoFiles openCryptoFiles;
	private CryptoFileSystemProperties fileSystemProperties;
	private CryptoPath cleartextPath;
	private Path ciphertextFilePath;
	private Symlinks symlinks;

	@BeforeEach
	public void setup() throws IOException {
		cryptor = Mockito.mock(Cryptor.class);
		pathMapper = Mockito.mock(CryptoPathMapper.class);
		openCryptoFiles = Mockito.mock(OpenCryptoFiles.class);
		fileSystemProperties = Mockito.mock(CryptoFileSystemProperties.class);
		cleartextPath = Mockito.mock(CryptoPath.class, "cleartextPath");
		ciphertextFilePath = Mockito.mock(Path.class, "ciphertextPath");
		symlinks = Mockito.mock(Symlinks.class);
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

		// needed for cleartxt file size calculation
		FileHeaderCryptor fileHeaderCryptor = Mockito.mock(FileHeaderCryptor.class);
		FileContentCryptor fileContentCryptor = Mockito.mock(FileContentCryptor.class);
		Mockito.when(cryptor.fileHeaderCryptor()).thenReturn(fileHeaderCryptor);
		Mockito.when(cryptor.fileContentCryptor()).thenReturn(fileContentCryptor);
		Mockito.when(fileHeaderCryptor.headerSize()).thenReturn(10);
		Mockito.when(fileContentCryptor.ciphertextChunkSize()).thenReturn(50);
		Mockito.when(fileContentCryptor.cleartextChunkSize()).thenReturn(40);

		// results in 2 full chunks = 80 cleartext bytes:
		Mockito.when(basicAttr.size()).thenReturn(110l);
		Mockito.when(posixAttr.size()).thenReturn(110l);
		Mockito.when(dosAttr.size()).thenReturn(110l);
	}

	@Nested
	public class Files {

		@BeforeEach
		public void setup() throws IOException {
			Mockito.when(pathMapper.getCiphertextFileType(cleartextPath)).thenReturn(CryptoPathMapper.CiphertextFileType.FILE);
			Mockito.when(pathMapper.getCiphertextFilePath(cleartextPath, CryptoPathMapper.CiphertextFileType.FILE)).thenReturn(ciphertextFilePath);
		}

		@Test
		public void testReadBasicAttributes() throws IOException {
			AttributeProvider prov = new AttributeProvider(cryptor, pathMapper, openCryptoFiles, fileSystemProperties, symlinks);
			BasicFileAttributes attr = prov.readAttributes(cleartextPath, BasicFileAttributes.class);
			Assertions.assertTrue(attr instanceof BasicFileAttributes);
			Assertions.assertTrue(attr.isRegularFile());
		}

		@Test
		public void testReadPosixAttributes() throws IOException {
			AttributeProvider prov = new AttributeProvider(cryptor, pathMapper, openCryptoFiles, fileSystemProperties, symlinks);
			PosixFileAttributes attr = prov.readAttributes(cleartextPath, PosixFileAttributes.class);
			Assertions.assertTrue(attr instanceof PosixFileAttributes);
			Assertions.assertTrue(attr.isRegularFile());
		}

		@Test
		public void testReadDosAttributes() throws IOException {
			AttributeProvider prov = new AttributeProvider(cryptor, pathMapper, openCryptoFiles, fileSystemProperties, symlinks);
			DosFileAttributes attr = prov.readAttributes(cleartextPath, DosFileAttributes.class);
			Assertions.assertTrue(attr instanceof DosFileAttributes);
			Assertions.assertTrue(attr.isRegularFile());
		}

		@Test
		public void testReadUnsupportedAttributes() {
			AttributeProvider prov = new AttributeProvider(cryptor, pathMapper, openCryptoFiles, fileSystemProperties, symlinks);

			Assertions.assertThrows(UnsupportedOperationException.class, () -> {
				prov.readAttributes(cleartextPath, UnsupportedAttributes.class);
			});
		}

	}

	@Nested
	public class Directories {

		@BeforeEach
		public void setup() throws IOException {
			Mockito.when(pathMapper.getCiphertextFileType(cleartextPath)).thenReturn(CryptoPathMapper.CiphertextFileType.DIRECTORY);
			Mockito.when(pathMapper.getCiphertextDir(cleartextPath)).thenReturn(new CiphertextDirectory("foo", ciphertextFilePath));
		}

		@Test
		public void testReadBasicAttributes() throws IOException {
			AttributeProvider prov = new AttributeProvider(cryptor, pathMapper, openCryptoFiles, fileSystemProperties, symlinks);
			BasicFileAttributes attr = prov.readAttributes(cleartextPath, BasicFileAttributes.class);
			Assertions.assertTrue(attr instanceof BasicFileAttributes);
			Assertions.assertTrue(attr.isDirectory());
		}

	}

	@Nested
	public class SymbolicLinks {

		@BeforeEach
		public void setup() throws IOException {
			Mockito.when(pathMapper.getCiphertextFileType(cleartextPath)).thenReturn(CryptoPathMapper.CiphertextFileType.SYMLINK);
		}

		@Test
		public void testReadBasicAttributesNoFollow() throws IOException {
			Mockito.when(pathMapper.getCiphertextFilePath(cleartextPath, CryptoPathMapper.CiphertextFileType.SYMLINK)).thenReturn(ciphertextFilePath);

			AttributeProvider prov = new AttributeProvider(cryptor, pathMapper, openCryptoFiles, fileSystemProperties, symlinks);
			BasicFileAttributes attr = prov.readAttributes(cleartextPath, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
			Assertions.assertTrue(attr instanceof BasicFileAttributes);
			Assertions.assertTrue(attr.isSymbolicLink());
		}

		@Test
		public void testReadBasicAttributesOfTarget() throws IOException {
			CryptoPath targetPath = Mockito.mock(CryptoPath.class, "targetPath");
			Mockito.when(symlinks.resolveRecursively(cleartextPath)).thenReturn(targetPath);
			Mockito.when(pathMapper.getCiphertextFileType(targetPath)).thenReturn(CryptoPathMapper.CiphertextFileType.FILE);
			Mockito.when(pathMapper.getCiphertextFilePath(targetPath, CryptoPathMapper.CiphertextFileType.FILE)).thenReturn(ciphertextFilePath);

			AttributeProvider prov = new AttributeProvider(cryptor, pathMapper, openCryptoFiles, fileSystemProperties, symlinks);
			BasicFileAttributes attr = prov.readAttributes(cleartextPath, BasicFileAttributes.class);
			Assertions.assertTrue(attr instanceof BasicFileAttributes);
			Assertions.assertTrue(attr.isRegularFile());
			Assertions.assertSame(80l, attr.size());
		}

	}


	private interface UnsupportedAttributes extends BasicFileAttributes {

	}

}
