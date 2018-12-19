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
import java.nio.file.FileSystemLoopException;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.DosFileAttributes;
import java.nio.file.attribute.PosixFileAttributes;
import java.nio.file.spi.FileSystemProvider;

import de.bechte.junit.runners.context.HierarchicalContextRunner;
import org.cryptomator.cryptolib.api.Cryptor;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mockito;

@RunWith(HierarchicalContextRunner.class)
public class CryptoFileAttributeProviderTest {

	private Cryptor cryptor;
	private CryptoPathMapper pathMapper;
	private OpenCryptoFiles openCryptoFiles;
	private CryptoFileSystemProperties fileSystemProperties;
	private CryptoPath cleartextPath;
	private Path ciphertextFilePath;
	private Symlinks symlinks;

	@Before
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
	}

	public class Files {

		@Before
		public void setup() throws IOException {
			Mockito.when(pathMapper.getCiphertextFileType(cleartextPath)).thenReturn(CryptoPathMapper.CiphertextFileType.FILE);
			Mockito.when(pathMapper.getCiphertextFilePath(cleartextPath, CryptoPathMapper.CiphertextFileType.FILE)).thenReturn(ciphertextFilePath);
		}

		@Test
		public void testReadBasicAttributes() throws IOException {
			CryptoFileAttributeProvider prov = new CryptoFileAttributeProvider(cryptor, pathMapper, openCryptoFiles, fileSystemProperties, symlinks);
			BasicFileAttributes attr = prov.readAttributes(cleartextPath, BasicFileAttributes.class);
			Assert.assertTrue(attr instanceof BasicFileAttributes);
			Assert.assertTrue(attr.isRegularFile());
		}

		@Test
		public void testReadPosixAttributes() throws IOException {
			CryptoFileAttributeProvider prov = new CryptoFileAttributeProvider(cryptor, pathMapper, openCryptoFiles, fileSystemProperties, symlinks);
			PosixFileAttributes attr = prov.readAttributes(cleartextPath, PosixFileAttributes.class);
			Assert.assertTrue(attr instanceof PosixFileAttributes);
			Assert.assertTrue(attr.isRegularFile());
		}

		@Test
		public void testReadDosAttributes() throws IOException {
			CryptoFileAttributeProvider prov = new CryptoFileAttributeProvider(cryptor, pathMapper, openCryptoFiles, fileSystemProperties, symlinks);
			DosFileAttributes attr = prov.readAttributes(cleartextPath, DosFileAttributes.class);
			Assert.assertTrue(attr instanceof DosFileAttributes);
			Assert.assertTrue(attr.isRegularFile());
		}

		@Test(expected = UnsupportedOperationException.class)
		public void testReadUnsupportedAttributes() throws IOException {
			CryptoFileAttributeProvider prov = new CryptoFileAttributeProvider(cryptor, pathMapper, openCryptoFiles, fileSystemProperties, symlinks);
			prov.readAttributes(cleartextPath, UnsupportedAttributes.class);
		}

	}

	public class Directories {

		@Before
		public void setup() throws IOException {
			Mockito.when(pathMapper.getCiphertextFileType(cleartextPath)).thenReturn(CryptoPathMapper.CiphertextFileType.DIRECTORY);
			Mockito.when(pathMapper.getCiphertextDirPath(cleartextPath)).thenReturn(ciphertextFilePath);
		}

		@Test
		public void testReadBasicAttributes() throws IOException {
			CryptoFileAttributeProvider prov = new CryptoFileAttributeProvider(cryptor, pathMapper, openCryptoFiles, fileSystemProperties, symlinks);
			BasicFileAttributes attr = prov.readAttributes(cleartextPath, BasicFileAttributes.class);
			Assert.assertTrue(attr instanceof BasicFileAttributes);
			Assert.assertTrue(attr.isDirectory());
		}

	}

	public class SymbolicLinks {

		@Before
		public void setup() throws IOException {
			Mockito.when(pathMapper.getCiphertextFileType(cleartextPath)).thenReturn(CryptoPathMapper.CiphertextFileType.SYMLINK);
		}

		@Test
		public void testReadBasicAttributesNoFollow() throws IOException {
			Mockito.when(pathMapper.getCiphertextFilePath(cleartextPath, CryptoPathMapper.CiphertextFileType.SYMLINK)).thenReturn(ciphertextFilePath);

			CryptoFileAttributeProvider prov = new CryptoFileAttributeProvider(cryptor, pathMapper, openCryptoFiles, fileSystemProperties, symlinks);
			BasicFileAttributes attr = prov.readAttributes(cleartextPath, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
			Assert.assertTrue(attr instanceof BasicFileAttributes);
			Assert.assertTrue(attr.isSymbolicLink());
		}

		@Test
		public void testReadBasicAttributesOfTarget() throws IOException {
			CryptoPath targetPath = Mockito.mock(CryptoPath.class, "targetPath");
			Mockito.when(symlinks.readSymbolicLink(cleartextPath)).thenReturn(targetPath);
			Mockito.when(pathMapper.getCiphertextFileType(targetPath)).thenReturn(CryptoPathMapper.CiphertextFileType.FILE);
			Mockito.when(pathMapper.getCiphertextFilePath(targetPath, CryptoPathMapper.CiphertextFileType.FILE)).thenReturn(ciphertextFilePath);

			CryptoFileAttributeProvider prov = new CryptoFileAttributeProvider(cryptor, pathMapper, openCryptoFiles, fileSystemProperties, symlinks);
			BasicFileAttributes attr = prov.readAttributes(cleartextPath, BasicFileAttributes.class);
			Assert.assertTrue(attr instanceof BasicFileAttributes);
			Assert.assertTrue(attr.isRegularFile());
		}

		@Test(expected = FileSystemLoopException.class)
		public void testFileSystemLoop() throws IOException {
			CryptoPath target1 = Mockito.mock(CryptoPath.class, "target1");
			CryptoPath target2 = Mockito.mock(CryptoPath.class, "target2");
			CryptoPath target3 = Mockito.mock(CryptoPath.class, "target3");
			Mockito.when(pathMapper.getCiphertextFileType(target1)).thenReturn(CryptoPathMapper.CiphertextFileType.SYMLINK);
			Mockito.when(pathMapper.getCiphertextFileType(target2)).thenReturn(CryptoPathMapper.CiphertextFileType.SYMLINK);
			Mockito.when(pathMapper.getCiphertextFileType(target3)).thenReturn(CryptoPathMapper.CiphertextFileType.SYMLINK);
			Mockito.when(symlinks.readSymbolicLink(target1)).thenReturn(target2);
			Mockito.when(symlinks.readSymbolicLink(target2)).thenReturn(target3);
			Mockito.when(symlinks.readSymbolicLink(target3)).thenReturn(target1);

			CryptoFileAttributeProvider prov = new CryptoFileAttributeProvider(cryptor, pathMapper, openCryptoFiles, fileSystemProperties, symlinks);
			prov.readAttributes(target1, BasicFileAttributes.class);
		}

	}


	private interface UnsupportedAttributes extends BasicFileAttributes {

	}

}
