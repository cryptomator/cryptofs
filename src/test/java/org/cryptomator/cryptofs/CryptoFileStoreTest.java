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
import org.hamcrest.CoreMatchers;
import org.hamcrest.MatcherAssert;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.io.IOException;
import java.nio.file.FileStore;
import java.nio.file.attribute.BasicFileAttributeView;
import java.nio.file.attribute.DosFileAttributeView;
import java.nio.file.attribute.FileAttributeView;
import java.nio.file.attribute.FileOwnerAttributeView;
import java.nio.file.attribute.PosixFileAttributeView;
import java.util.Optional;
import java.util.Set;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class CryptoFileStoreTest {
	
	private final ReadonlyFlag readonlyFlag = mock(ReadonlyFlag.class);
	
	@Nested
	@DisplayName("with delegate present")
	public class DelegatingCryptoFileStoreTest {

		private final FileStore delegate = mock(FileStore.class);
		private CryptoFileStore cryptoFileStore;

		@BeforeEach
		public void setup() {
			cryptoFileStore = new CryptoFileStore(Optional.of(delegate), readonlyFlag);
		}

		@Test
		public void testSupportedFileAttributeViewTypes() {
			when(delegate.supportsFileAttributeView(BasicFileAttributeView.class)).thenReturn(true);
			when(delegate.supportsFileAttributeView(PosixFileAttributeView.class)).thenReturn(true);
			when(delegate.supportsFileAttributeView(DosFileAttributeView.class)).thenReturn(true);
			when(delegate.supportsFileAttributeView(FileOwnerAttributeView.class)).thenReturn(true);
			cryptoFileStore = new CryptoFileStore(Optional.of(delegate), readonlyFlag);
			Set<AttributeViewType> result = cryptoFileStore.supportedFileAttributeViewTypes();
			MatcherAssert.assertThat(result, CoreMatchers.hasItems(AttributeViewType.BASIC, AttributeViewType.POSIX, AttributeViewType.DOS, AttributeViewType.OWNER));
		}

		@ParameterizedTest
		@ValueSource(booleans = {true, false})
		public void testIsReadonlyWithReadonlyFlag(boolean readonly) {
			when(readonlyFlag.isSet()).thenReturn(true);
			when(delegate.isReadOnly()).thenReturn(readonly);
			Assertions.assertTrue(cryptoFileStore.isReadOnly());
		}

		@ParameterizedTest
		@ValueSource(booleans = {true, false})
		public void testIsReadonlyWithoutReadonlyFlag(boolean readonly) {
			when(readonlyFlag.isSet()).thenReturn(false);
			when(delegate.isReadOnly()).thenReturn(readonly);
			Assertions.assertEquals(readonly, cryptoFileStore.isReadOnly());
		}

		@ParameterizedTest
		@ValueSource(longs = {-1, 0, 1, 42, 1337})
		public void testGetTotalSpace(long num) throws IOException {
			when(delegate.getTotalSpace()).thenReturn(num);
			Assertions.assertEquals(num, cryptoFileStore.getTotalSpace());
		}

		@ParameterizedTest
		@ValueSource(longs = {-1, 0, 1, 42, 1337})
		public void testGetUsableSpace(long num) throws IOException {
			when(delegate.getUsableSpace()).thenReturn(num);
			Assertions.assertEquals(num, cryptoFileStore.getUsableSpace());
		}

		@ParameterizedTest
		@ValueSource(longs = {-1, 0, 1, 42, 1337})
		public void testGetUnallocatedSpace(long num) throws IOException {
			when(delegate.getUnallocatedSpace()).thenReturn(num);
			Assertions.assertEquals(num, cryptoFileStore.getUnallocatedSpace());
		}

		@ParameterizedTest
		@ValueSource(classes = {BasicFileAttributeView.class, PosixFileAttributeView.class, DosFileAttributeView.class, FileOwnerAttributeView.class})
		public void testSupportsFileAttributeViewByType(Class<? extends FileAttributeView> clazz) {
			when(delegate.supportsFileAttributeView(clazz)).thenReturn(true, false);
			Assertions.assertTrue(cryptoFileStore.supportsFileAttributeView(clazz));
			Assertions.assertFalse(cryptoFileStore.supportsFileAttributeView(clazz));
		}

		@ParameterizedTest
		@ValueSource(strings = {"basic", "posix", "dos", "owner"})
		public void testSupportsFileAttributeViewByName(String name) {
			when(delegate.supportsFileAttributeView(name)).thenReturn(true, false);
			Assertions.assertTrue(cryptoFileStore.supportsFileAttributeView(name));
			Assertions.assertFalse(cryptoFileStore.supportsFileAttributeView(name));
		}

		@Test
		public void testGetFileStoreAttributeView() {
			Assertions.assertNull(cryptoFileStore.getFileStoreAttributeView(null));
		}

		@Test
		public void testGetAttribute() {
			Assertions.assertThrows(UnsupportedOperationException.class, () -> {
				cryptoFileStore.getAttribute(null);
			});
		}
		
	}

	@Nested
	@DisplayName("with delegate absent")
	public class FallbackCryptoFileStoreTest {
		
		private CryptoFileStore cryptoFileStore;
		
		@BeforeEach
		public void setup() {
			cryptoFileStore = new CryptoFileStore(Optional.empty(), readonlyFlag);
		}
		
		@Test
		public void testSupportedFileAttributeViewTypes() {
			Set<AttributeViewType> result = cryptoFileStore.supportedFileAttributeViewTypes();
			MatcherAssert.assertThat(result, CoreMatchers.hasItems(AttributeViewType.BASIC));
		}

		@Test
		public void testIsReadonly() {
			when(readonlyFlag.isSet()).thenReturn(true, false);
			Assertions.assertTrue(cryptoFileStore.isReadOnly());
			Assertions.assertFalse(cryptoFileStore.isReadOnly());
		}
		
		@Test
		public void testGetTotalSpace() throws IOException {
			Assertions.assertEquals(CryptoFileStore.DEFAULT_TOTAL_SPACE, cryptoFileStore.getTotalSpace());
		}

		@Test
		public void testGetUsableSpace() throws IOException {
			Assertions.assertEquals(CryptoFileStore.DEFAULT_USABLE_SPACE, cryptoFileStore.getUsableSpace());
		}

		@Test
		public void testGetUnallocatedSpace() throws IOException {
			Assertions.assertEquals(CryptoFileStore.DEFAULT_UNALLOCATED_SPACE, cryptoFileStore.getUnallocatedSpace());
		}

		@Test
		public void testSupportsFileAttributeViewByType() {
			Assertions.assertTrue(cryptoFileStore.supportsFileAttributeView(BasicFileAttributeView.class));
		}

		@Test
		public void testSupportsFileAttributeViewByName() {
			Assertions.assertTrue(cryptoFileStore.supportsFileAttributeView("basic"));
		}
		
		@Test
		public void testGetFileStoreAttributeView() {
			Assertions.assertNull(cryptoFileStore.getFileStoreAttributeView(null));
		}

		@Test
		public void testGetAttribute() {
			Assertions.assertThrows(UnsupportedOperationException.class, () -> {
				cryptoFileStore.getAttribute(null);
			});
		}

	}

}
