package org.cryptomator.cryptofs.attr;

import org.cryptomator.cryptofs.CryptoFileSystemProperties;
import org.cryptomator.cryptofs.CryptoPath;
import org.cryptomator.cryptofs.fh.OpenCryptoFile;
import org.cryptomator.cryptolib.api.Cryptor;
import org.cryptomator.cryptolib.api.FileContentCryptor;
import org.cryptomator.cryptolib.api.FileHeaderCryptor;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import java.nio.file.attribute.DosFileAttributes;
import java.util.Optional;

import static org.cryptomator.cryptofs.common.CiphertextFileType.FILE;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class CryptoDosFileAttributesTest {

	private DosFileAttributes delegate = mock(DosFileAttributes.class);
	private CryptoPath path = mock(CryptoPath.class);
	private Cryptor cryptor = mock(Cryptor.class);
	private FileHeaderCryptor headerCryptor = mock(FileHeaderCryptor.class);
	private FileContentCryptor contentCryptor = mock(FileContentCryptor.class);
	private OpenCryptoFile openCryptoFile = mock(OpenCryptoFile.class);
	private CryptoFileSystemProperties cryptoFileSystemProperties = mock(CryptoFileSystemProperties.class);

	@BeforeEach
	public void setup() {
		when(delegate.size()).thenReturn(0L);
		when(cryptor.fileHeaderCryptor()).thenReturn(headerCryptor);
		when(cryptor.fileContentCryptor()).thenReturn(contentCryptor);
		when(headerCryptor.headerSize()).thenReturn(0);
		when(contentCryptor.ciphertextChunkSize()).thenReturn(100);
		when(contentCryptor.cleartextChunkSize()).thenReturn(100);
	}

	@Nested
	@DisplayName("on read-write filesystem")
	public class ReadWriteFileSystem {

		private CryptoDosFileAttributes inTest;

		@BeforeEach
		public void beforeEach() {
			when(cryptoFileSystemProperties.readonly()).thenReturn(false);
		}

		@DisplayName("isArchive()")
		@ParameterizedTest(name = "is {0} if delegate.isArchive() is {0}")
		@CsvSource({"true", "false"})
		public void testIsArchiveImmutable(boolean value) {
			when(delegate.isArchive()).thenReturn(value);
			inTest = new CryptoDosFileAttributes(delegate, FILE, path, cryptor, Optional.of(openCryptoFile), cryptoFileSystemProperties);

			verify(delegate, times(1)).isArchive();
			Assertions.assertEquals(value, inTest.isArchive());
			verify(delegate, times(1)).isArchive();
		}

		@DisplayName("isHidden()")
		@ParameterizedTest(name = "is {0} if delegate.isHidden() is {0}")
		@CsvSource({"true", "false"})
		public void testIsHiddenImmutable(boolean value) {
			when(delegate.isHidden()).thenReturn(value);
			inTest = new CryptoDosFileAttributes(delegate, FILE, path, cryptor, Optional.of(openCryptoFile), cryptoFileSystemProperties);

			verify(delegate, times(1)).isHidden();
			Assertions.assertEquals(value, inTest.isHidden());
			verify(delegate, times(1)).isHidden();
		}

		@DisplayName("isReadOnly()")
		@ParameterizedTest(name = "is {0} if delegate.readOnly() is {0}")
		@CsvSource({"true", "false"})
		public void testIsReadOnlyImmutable(boolean value) {
			when(delegate.isReadOnly()).thenReturn(value);
			inTest = new CryptoDosFileAttributes(delegate, FILE, path, cryptor, Optional.of(openCryptoFile), cryptoFileSystemProperties);

			verify(delegate, times(1)).isReadOnly();
			Assertions.assertEquals(value, inTest.isReadOnly());
			verify(delegate, times(1)).isReadOnly();
		}

		@DisplayName("isSystem()")
		@ParameterizedTest(name = "is {0} if delegate.isSystem() is {0}")
		@CsvSource({"true", "false"})
		public void testIsSystemImmutable(boolean value) {
			when(delegate.isSystem()).thenReturn(value);
			inTest = new CryptoDosFileAttributes(delegate, FILE, path, cryptor, Optional.of(openCryptoFile), cryptoFileSystemProperties);

			verify(delegate, times(1)).isSystem();
			Assertions.assertEquals(value, inTest.isSystem());
			verify(delegate, times(1)).isSystem();
		}

	}

	@Nested
	@DisplayName("on read-only filesystem")
	public class ReadOnlyFileSystem {

		@BeforeEach
		public void beforeEach() {
			when(cryptoFileSystemProperties.readonly()).thenReturn(true);
		}

		@DisplayName("isReadOnly()")
		@ParameterizedTest(name = "is true if delegate.readOnly() is {0}")
		@CsvSource({"true", "false"})
		public void testIsReadOnlyForReadonlyFileSystem(boolean value) {
			when(delegate.isReadOnly()).thenReturn(value);
			var inTest = new CryptoDosFileAttributes(delegate, FILE, path, cryptor, Optional.of(openCryptoFile), cryptoFileSystemProperties);

			verify(delegate, Mockito.atMostOnce()).isReadOnly();
			Assertions.assertTrue(inTest.isReadOnly());
			verify(delegate, Mockito.atMostOnce()).isReadOnly();
		}
	}
}
