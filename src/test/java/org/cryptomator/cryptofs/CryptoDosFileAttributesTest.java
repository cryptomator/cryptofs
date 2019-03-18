package org.cryptomator.cryptofs;

import org.cryptomator.cryptofs.fh.OpenCryptoFile;
import org.cryptomator.cryptolib.api.Cryptor;
import org.cryptomator.cryptolib.api.FileContentCryptor;
import org.cryptomator.cryptolib.api.FileHeaderCryptor;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import java.nio.file.attribute.DosFileAttributes;
import java.util.Optional;
import java.util.stream.Stream;

import static org.cryptomator.cryptofs.CryptoPathMapper.CiphertextFileType.FILE;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class CryptoDosFileAttributesTest {

	private DosFileAttributes delegate = mock(DosFileAttributes.class);
	private CryptoPath path = mock(CryptoPath.class);
	private Cryptor cryptor = mock(Cryptor.class);
	private FileHeaderCryptor headerCryptor = mock(FileHeaderCryptor.class);
	private FileContentCryptor contentCryptor = mock(FileContentCryptor.class);
	private OpenCryptoFile openCryptoFile = mock(OpenCryptoFile.class);

	private CryptoDosFileAttributes inTest;

	@BeforeEach
	public void setup() {
		when(delegate.size()).thenReturn(0l);
		when(cryptor.fileHeaderCryptor()).thenReturn(headerCryptor);
		when(cryptor.fileContentCryptor()).thenReturn(contentCryptor);
		when(headerCryptor.headerSize()).thenReturn(0);
		when(contentCryptor.ciphertextChunkSize()).thenReturn(100);
		when(contentCryptor.cleartextChunkSize()).thenReturn(100);

		inTest = new CryptoDosFileAttributes(delegate, FILE, path, cryptor, Optional.of(openCryptoFile), false);
	}

	@Test
	public void testIsArchiveDelegates() {
		Assertions.assertFalse(inTest.isArchive());
	}

	@Test
	public void testIsHiddenIsFAlse() {
		Assertions.assertFalse(inTest.isHidden());
	}

	@ParameterizedTest
	@MethodSource("booleans")
	public void testIsReadOnlyDelegates(boolean value) {
		when(delegate.isReadOnly()).thenReturn(value);

		CryptoDosFileAttributes attrs = new CryptoDosFileAttributes(delegate, FILE, path, cryptor, Optional.of(openCryptoFile), false);
		Assertions.assertSame(value, attrs.isReadOnly());
	}

	@ParameterizedTest
	@MethodSource("booleans")
	public void testIsReadOnlyForReadonlyFileSystem(boolean value) {
		when(delegate.isReadOnly()).thenReturn(value);

		CryptoDosFileAttributes attrs = new CryptoDosFileAttributes(delegate, FILE, path, cryptor, Optional.of(openCryptoFile), true);
		Assertions.assertTrue(attrs.isReadOnly());
	}

	@Test
	public void testIsSystemDelegates() {
		Assertions.assertFalse(inTest.isSystem());
	}

	private static final Stream<Boolean> booleans() {
		return Stream.of(Boolean.TRUE, Boolean.FALSE);
	}

}
