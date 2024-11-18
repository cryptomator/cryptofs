/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptofs.attr;

import org.cryptomator.cryptofs.CiphertextDirectory;
import org.cryptomator.cryptofs.CiphertextFilePath;
import org.cryptomator.cryptofs.CryptoPath;
import org.cryptomator.cryptofs.CryptoPathMapper;
import org.cryptomator.cryptofs.Symlinks;
import org.cryptomator.cryptofs.common.CiphertextFileType;
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

import static org.mockito.ArgumentMatchers.any;

public class AttributeProviderTest {

	private AttributeComponent.Factory attributeComponentFactory;
	private AttributeComponent attributeComponent;
	private CryptoPathMapper pathMapper;
	private CryptoPath cleartextPath;
	private CiphertextFilePath ciphertextPath;
	private Path ciphertextRawPath;
	private Symlinks symlinks;
	private BasicFileAttributes ciphertextBasicAttr;
	private PosixFileAttributes ciphertextPosixAttr;
	private DosFileAttributes ciphertextDosAttr;

	@BeforeEach
	public void setup() throws IOException {
		attributeComponentFactory = Mockito.mock(AttributeComponent.Factory.class);
		attributeComponent = Mockito.mock(AttributeComponent.class);
		Mockito.when(attributeComponentFactory.create(any(), any(), any())).thenReturn(attributeComponent);

		pathMapper = Mockito.mock(CryptoPathMapper.class);
		cleartextPath = Mockito.mock(CryptoPath.class, "cleartextPath");
		ciphertextRawPath = Mockito.mock(Path.class, "ciphertextPath");
		ciphertextPath = Mockito.mock(CiphertextFilePath.class);
		symlinks = Mockito.mock(Symlinks.class);
		FileSystem fs = Mockito.mock(FileSystem.class);
		Mockito.when(ciphertextRawPath.getFileSystem()).thenReturn(fs);
		FileSystemProvider provider = Mockito.mock(FileSystemProvider.class);
		Mockito.when(fs.provider()).thenReturn(provider);
		ciphertextBasicAttr = Mockito.mock(BasicFileAttributes.class);
		ciphertextPosixAttr = Mockito.mock(PosixFileAttributes.class);
		ciphertextDosAttr = Mockito.mock(DosFileAttributes.class);
		Mockito.when(provider.readAttributes(Mockito.same(ciphertextRawPath), Mockito.same(BasicFileAttributes.class), any(LinkOption[].class))).thenReturn(ciphertextBasicAttr);
		Mockito.when(provider.readAttributes(Mockito.same(ciphertextRawPath), Mockito.same(PosixFileAttributes.class), any(LinkOption[].class))).thenReturn(ciphertextPosixAttr);
		Mockito.when(provider.readAttributes(Mockito.same(ciphertextRawPath), Mockito.same(DosFileAttributes.class), any(LinkOption[].class))).thenReturn(ciphertextDosAttr);

		Mockito.when(pathMapper.getCiphertextFileType(cleartextPath)).thenReturn(CiphertextFileType.FILE);
		Mockito.when(pathMapper.getCiphertextFilePath(cleartextPath)).thenReturn(ciphertextPath);
		Mockito.when(ciphertextPath.getRawPath()).thenReturn(ciphertextRawPath);
		Mockito.when(ciphertextPath.getFilePath()).thenReturn(ciphertextRawPath);
		Mockito.when(ciphertextPath.getDirFilePath()).thenReturn(ciphertextRawPath);
		Mockito.when(ciphertextPath.getSymlinkFilePath()).thenReturn(ciphertextRawPath);

	}

	@Nested
	public class Files {

		private AttributeProvider prov;

		@BeforeEach
		public void setup() throws IOException {
			Mockito.when(symlinks.resolveRecursively(cleartextPath)).thenReturn(cleartextPath);
			Mockito.when(pathMapper.getCiphertextFileType(cleartextPath)).thenReturn(CiphertextFileType.FILE);
			Mockito.when(pathMapper.getCiphertextFilePath(cleartextPath)).thenReturn(ciphertextPath);

			prov = new AttributeProvider(attributeComponentFactory, pathMapper, symlinks);
		}

		@Test
		public void testReadBasicAttributes() throws IOException {
			Mockito.when(attributeComponent.attributes(BasicFileAttributes.class)).thenReturn(ciphertextBasicAttr);

			BasicFileAttributes attr = prov.readAttributes(cleartextPath, BasicFileAttributes.class);

			Mockito.verify(attributeComponentFactory, Mockito.times(1)).create(ciphertextRawPath, CiphertextFileType.FILE, ciphertextBasicAttr);
			Assertions.assertEquals(ciphertextBasicAttr, attr);
		}

		@Test
		public void testReadPosixAttributes() throws IOException {
			Mockito.when(attributeComponent.attributes(PosixFileAttributes.class)).thenReturn(ciphertextPosixAttr);

			PosixFileAttributes attr = prov.readAttributes(cleartextPath, PosixFileAttributes.class);

			Mockito.verify(attributeComponentFactory, Mockito.times(1)).create(ciphertextRawPath, CiphertextFileType.FILE, ciphertextPosixAttr);
			Assertions.assertEquals(ciphertextPosixAttr, attr);
		}

		@Test
		public void testReadDosAttributes() throws IOException {
			Mockito.when(attributeComponent.attributes(DosFileAttributes.class)).thenReturn(ciphertextDosAttr);

			DosFileAttributes attr = prov.readAttributes(cleartextPath, DosFileAttributes.class);

			Mockito.verify(attributeComponentFactory, Mockito.times(1)).create(ciphertextRawPath, CiphertextFileType.FILE, ciphertextDosAttr);
			Assertions.assertEquals(ciphertextDosAttr, attr);
		}

		@Test
		public void testReadUnsupportedAttributes() {
			Mockito.when(attributeComponent.attributes(UnsupportedAttributes.class)).thenThrow(UnsupportedOperationException.class);

			Assertions.assertThrows(UnsupportedOperationException.class, () -> {
				prov.readAttributes(cleartextPath, UnsupportedAttributes.class);
			});
			Mockito.verify(attributeComponentFactory, Mockito.times(1)).create(Mockito.eq(ciphertextRawPath), Mockito.eq(CiphertextFileType.FILE), any());
		}

	}

	@Nested
	public class Directories {

		private AttributeProvider prov;

		@BeforeEach
		public void setup() throws IOException {
			Mockito.when(symlinks.resolveRecursively(cleartextPath)).thenReturn(cleartextPath);
			Mockito.when(pathMapper.getCiphertextFileType(cleartextPath)).thenReturn(CiphertextFileType.DIRECTORY);
			Mockito.when(pathMapper.getCiphertextDir(cleartextPath)).thenReturn(new CiphertextDirectory("foo", ciphertextRawPath));

			prov = new AttributeProvider(attributeComponentFactory, pathMapper, symlinks);
		}

		@Test
		public void testReadBasicAttributes() throws IOException {
			Mockito.when(attributeComponent.attributes(BasicFileAttributes.class)).thenReturn(ciphertextBasicAttr);

			BasicFileAttributes attr = prov.readAttributes(cleartextPath, BasicFileAttributes.class);

			Mockito.verify(attributeComponentFactory, Mockito.times(1)).create(ciphertextRawPath, CiphertextFileType.DIRECTORY, ciphertextBasicAttr);
			Assertions.assertEquals(ciphertextBasicAttr, attr);
		}

	}

	@Nested
	public class SymbolicLinks {

		private AttributeProvider prov;

		@BeforeEach
		public void setup() throws IOException {
			Mockito.when(pathMapper.getCiphertextFileType(cleartextPath)).thenReturn(CiphertextFileType.SYMLINK);

			prov = new AttributeProvider(attributeComponentFactory, pathMapper, symlinks);
		}

		@Test
		public void testReadBasicAttributesNoFollow() throws IOException {
			Mockito.when(symlinks.resolveRecursively(cleartextPath)).thenReturn(cleartextPath);
			Mockito.when(pathMapper.getCiphertextFilePath(cleartextPath)).thenReturn(ciphertextPath);
			Mockito.when(attributeComponent.attributes(BasicFileAttributes.class)).thenReturn(ciphertextBasicAttr);

			BasicFileAttributes attr = prov.readAttributes(cleartextPath, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);

			Mockito.verify(attributeComponentFactory, Mockito.times(1)).create(ciphertextRawPath, CiphertextFileType.SYMLINK, ciphertextBasicAttr);
			Assertions.assertEquals(ciphertextBasicAttr, attr);
		}

		@Test
		public void testReadBasicAttributesOfTarget() throws IOException {
			CryptoPath targetPath = Mockito.mock(CryptoPath.class, "targetPath");
			Mockito.when(symlinks.resolveRecursively(cleartextPath)).thenReturn(targetPath);
			Mockito.when(pathMapper.getCiphertextFileType(targetPath)).thenReturn(CiphertextFileType.FILE);
			Mockito.when(pathMapper.getCiphertextFilePath(targetPath)).thenReturn(ciphertextPath);
			Mockito.when(attributeComponent.attributes(BasicFileAttributes.class)).thenReturn(ciphertextBasicAttr);

			BasicFileAttributes attr = prov.readAttributes(cleartextPath, BasicFileAttributes.class);

			Mockito.verify(attributeComponentFactory, Mockito.times(1)).create(ciphertextRawPath, CiphertextFileType.FILE, ciphertextBasicAttr);
			Assertions.assertEquals(ciphertextBasicAttr, attr);
		}

	}


	private interface UnsupportedAttributes extends BasicFileAttributes {

	}

}
