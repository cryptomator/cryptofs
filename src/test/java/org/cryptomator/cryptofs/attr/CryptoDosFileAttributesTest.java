package org.cryptomator.cryptofs.attr;

import org.cryptomator.cryptofs.CryptoFileSystemProperties;
import org.cryptomator.cryptofs.CryptoPath;
import org.cryptomator.cryptofs.fh.OpenCryptoFile;
import org.cryptomator.cryptolib.api.Cryptor;
import org.cryptomator.cryptolib.api.FileContentCryptor;
import org.cryptomator.cryptolib.api.FileHeaderCryptor;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import java.nio.file.attribute.DosFileAttributes;
import java.util.Optional;

import static org.cryptomator.cryptofs.common.CiphertextFileType.FILE;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public class CryptoDosFileAttributesTest {

	private DosFileAttributes delegate = mock(DosFileAttributes.class);
	private CryptoPath path = mock(CryptoPath.class);
	private Cryptor cryptor = mock(Cryptor.class);
	private FileHeaderCryptor headerCryptor = mock(FileHeaderCryptor.class);
	private FileContentCryptor contentCryptor = mock(FileContentCryptor.class);
	private OpenCryptoFile openCryptoFile = mock(OpenCryptoFile.class);
	private CryptoFileSystemProperties cryptoFileSystemProperties = mock(CryptoFileSystemProperties.class);

	@BeforeAll
	public void setup() {
		when(delegate.size()).thenReturn(0l);
		when(cryptor.fileHeaderCryptor()).thenReturn(headerCryptor);
		when(cryptor.fileContentCryptor()).thenReturn(contentCryptor);
		when(headerCryptor.headerSize()).thenReturn(0);
		when(contentCryptor.ciphertextChunkSize()).thenReturn(100);
		when(contentCryptor.cleartextChunkSize()).thenReturn(100);
	}

	@Nested
	@TestInstance(TestInstance.Lifecycle.PER_CLASS)
	@DisplayName("on read-write filesystem")
	public class ReadWriteFileSystem {

		private CryptoDosFileAttributes inTest;

		@BeforeAll
		public void setup() {
			when(cryptoFileSystemProperties.readonly()).thenReturn(false);
			inTest = new CryptoDosFileAttributes(delegate, FILE, path, cryptor, Optional.of(openCryptoFile), cryptoFileSystemProperties);
		}

		@DisplayName("isArchive()")
		@ParameterizedTest(name = "is {0} if delegate.isArchive() is {0}")
		@CsvSource({"true", "false"})
		public void testIsArchiveDelegates(boolean value) {
			when(delegate.isArchive()).thenReturn(value);

			Assertions.assertSame(value, inTest.isArchive());
		}

		@DisplayName("isHidden()")
		@ParameterizedTest(name = "is {0} if delegate.isHidden() is {0}")
		@CsvSource({"true", "false"})
		public void testIsHiddenDelegates(boolean value) {
			when(delegate.isHidden()).thenReturn(value);

			Assertions.assertSame(value, inTest.isHidden());
		}

		@DisplayName("isReadOnly()")
		@ParameterizedTest(name = "is {0} if delegate.readOnly() is {0}")
		@CsvSource({"true", "false"})
		public void testIsReadOnlyDelegates(boolean value) {
			when(delegate.isReadOnly()).thenReturn(value);

			Assertions.assertSame(value, inTest.isReadOnly());
		}

		@DisplayName("isSystem()")
		@ParameterizedTest(name = "is {0} if delegate.isSystem() is {0}")
		@CsvSource({"true", "false"})
		public void testIsSystemDelegates(boolean value) {
			when(delegate.isSystem()).thenReturn(value);

			Assertions.assertSame(value, inTest.isSystem());
		}

	}

	@Nested
	@TestInstance(TestInstance.Lifecycle.PER_CLASS)
	@DisplayName("on read-only filesystem")
	public class ReadOnlyFileSystem {

		private CryptoDosFileAttributes inTest;

		@BeforeAll
		public void setup() {
			when(cryptoFileSystemProperties.readonly()).thenReturn(true);
			inTest = new CryptoDosFileAttributes(delegate, FILE, path, cryptor, Optional.of(openCryptoFile), cryptoFileSystemProperties);
		}

		@DisplayName("isReadOnly()")
		@ParameterizedTest(name = "is true if delegate.readOnly() is {0}")
		@CsvSource({"true", "false"})
		public void testIsReadOnlyForReadonlyFileSystem(boolean value) {
			when(delegate.isReadOnly()).thenReturn(value);

			Assertions.assertTrue(inTest.isReadOnly());
		}

	}
}
