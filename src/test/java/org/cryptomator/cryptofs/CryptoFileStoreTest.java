/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptofs;

import org.cryptomator.cryptofs.attr.AttributeViewType;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.FileStore;
import java.nio.file.FileSystem;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributeView;
import java.nio.file.attribute.DosFileAttributeView;
import java.nio.file.attribute.FileOwnerAttributeView;
import java.nio.file.attribute.PosixFileAttributeView;
import java.nio.file.spi.FileSystemProvider;
import java.util.Set;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class CryptoFileStoreTest {

	private final Path path = mock(Path.class);
	private final FileSystemProvider provider = mock(FileSystemProvider.class);
	private final FileSystem fileSystem = mock(FileSystem.class);
	private final FileStore delegate = mock(FileStore.class);
	private final ReadonlyFlag readonlyFlag = mock(ReadonlyFlag.class);

	@BeforeEach
	public void setUp() throws IOException {
		when(path.getFileSystem()).thenReturn(fileSystem);
		when(fileSystem.provider()).thenReturn(provider);
		when(provider.getFileStore(path)).thenReturn(delegate);
	}

	@Test
	public void testIsReadonlyReturnsTrueIfReadonlyFlagIsSet() {
		when(readonlyFlag.isSet()).thenReturn(true);

		CryptoFileStore inTest = new CryptoFileStore(path, readonlyFlag);

		Assertions.assertTrue(inTest.isReadOnly());
	}

	@Test
	public void testIsReadonlyReturnsFalseIfReadonlyFlagIsNotSet() {
		when(readonlyFlag.isSet()).thenReturn(false);

		CryptoFileStore inTest = new CryptoFileStore(path, readonlyFlag);

		Assertions.assertFalse(inTest.isReadOnly());
	}

	@Test
	public void testSupportedFileAttributeViewTypes() {
		when(delegate.supportsFileAttributeView(PosixFileAttributeView.class)).thenReturn(true);
		when(delegate.supportsFileAttributeView(FileOwnerAttributeView.class)).thenReturn(true);
		when(delegate.supportsFileAttributeView(BasicFileAttributeView.class)).thenReturn(true);
		when(delegate.supportsFileAttributeView(DosFileAttributeView.class)).thenReturn(false);

		CryptoFileStore inTest = new CryptoFileStore(path, readonlyFlag);

		Set<AttributeViewType> result = inTest.supportedFileAttributeViewTypes();
		Assertions.assertTrue(result.contains(AttributeViewType.POSIX));
		Assertions.assertTrue(result.contains(AttributeViewType.OWNER));
		Assertions.assertTrue(result.contains(AttributeViewType.BASIC));
		Assertions.assertFalse(result.contains(AttributeViewType.DOS));
	}

	@Test
	public void testSupportsFileAttributeViewByType() {
		when(delegate.supportsFileAttributeView(PosixFileAttributeView.class)).thenReturn(true);
		when(delegate.supportsFileAttributeView(FileOwnerAttributeView.class)).thenReturn(true);
		when(delegate.supportsFileAttributeView(BasicFileAttributeView.class)).thenReturn(true);
		when(delegate.supportsFileAttributeView(DosFileAttributeView.class)).thenReturn(false);

		CryptoFileStore inTest = new CryptoFileStore(path, readonlyFlag);

		Assertions.assertTrue(inTest.supportsFileAttributeView(PosixFileAttributeView.class));
		Assertions.assertTrue(inTest.supportsFileAttributeView(FileOwnerAttributeView.class));
		Assertions.assertTrue(inTest.supportsFileAttributeView(BasicFileAttributeView.class));
		Assertions.assertFalse(inTest.supportsFileAttributeView(DosFileAttributeView.class));
	}

	@Test
	public void testSupportsFileAttributeViewByName() {
		when(delegate.supportsFileAttributeView(PosixFileAttributeView.class)).thenReturn(true);
		when(delegate.supportsFileAttributeView(FileOwnerAttributeView.class)).thenReturn(true);
		when(delegate.supportsFileAttributeView(BasicFileAttributeView.class)).thenReturn(true);
		when(delegate.supportsFileAttributeView(DosFileAttributeView.class)).thenReturn(false);

		CryptoFileStore inTest = new CryptoFileStore(path, readonlyFlag);

		Assertions.assertTrue(inTest.supportsFileAttributeView("posix"));
		Assertions.assertTrue(inTest.supportsFileAttributeView("owner"));
		Assertions.assertTrue(inTest.supportsFileAttributeView("basic"));
		Assertions.assertFalse(inTest.supportsFileAttributeView("dos"));
	}

	@Test
	public void testRethrowsIOExceptionFromGetFileStoreUnchecked() throws IOException {
		IOException expected = new IOException();
		when(provider.getFileStore(path)).thenThrow(expected);

		UncheckedIOException e = Assertions.assertThrows(UncheckedIOException.class, () -> {
			new CryptoFileStore(path, readonlyFlag);
		});
		Assertions.assertSame(expected, e.getCause());
	}

}
