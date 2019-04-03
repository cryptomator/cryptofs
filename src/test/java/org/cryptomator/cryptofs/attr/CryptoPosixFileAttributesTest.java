package org.cryptomator.cryptofs.attr;

import org.cryptomator.cryptofs.attr.CryptoPosixFileAttributes;
import org.cryptomator.cryptofs.fh.OpenCryptoFile;
import org.cryptomator.cryptolib.api.Cryptor;
import org.cryptomator.cryptolib.api.FileContentCryptor;
import org.cryptomator.cryptolib.api.FileHeaderCryptor;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.nio.file.attribute.PosixFileAttributes;
import java.nio.file.attribute.PosixFilePermission;
import java.util.EnumSet;
import java.util.Optional;
import java.util.Set;

import static java.nio.file.attribute.PosixFilePermission.GROUP_EXECUTE;
import static java.nio.file.attribute.PosixFilePermission.GROUP_READ;
import static java.nio.file.attribute.PosixFilePermission.OTHERS_EXECUTE;
import static java.nio.file.attribute.PosixFilePermission.OTHERS_READ;
import static java.nio.file.attribute.PosixFilePermission.OWNER_EXECUTE;
import static java.nio.file.attribute.PosixFilePermission.OWNER_READ;
import static org.cryptomator.cryptofs.CryptoPathMapper.CiphertextFileType.FILE;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class CryptoPosixFileAttributesTest {

	private PosixFileAttributes delegate = mock(PosixFileAttributes.class);
	private Cryptor cryptor = mock(Cryptor.class);
	private FileHeaderCryptor headerCryptor = mock(FileHeaderCryptor.class);
	private FileContentCryptor contentCryptor = mock(FileContentCryptor.class);
	private OpenCryptoFile openCryptoFile = mock(OpenCryptoFile.class);

	@BeforeEach
	public void setup() {
		when(delegate.size()).thenReturn(0l);
		when(cryptor.fileHeaderCryptor()).thenReturn(headerCryptor);
		when(cryptor.fileContentCryptor()).thenReturn(contentCryptor);
		when(headerCryptor.headerSize()).thenReturn(0);
		when(contentCryptor.ciphertextChunkSize()).thenReturn(100);
		when(contentCryptor.cleartextChunkSize()).thenReturn(100);
	}

	@Test
	public void testGetPermissions() {
		Set<PosixFilePermission> delegatePermissions = EnumSet.allOf(PosixFilePermission.class);
		Mockito.when(delegate.permissions()).thenReturn(delegatePermissions);

		CryptoPosixFileAttributes attrs = new CryptoPosixFileAttributes(delegate, FILE,null, cryptor, Optional.of(openCryptoFile), false);
		Assertions.assertArrayEquals(delegatePermissions.toArray(), attrs.permissions().toArray());
	}

	@Test
	public void testGetPermissionsReadOnly() {
		Set<PosixFilePermission> delegatePermissions = EnumSet.allOf(PosixFilePermission.class);
		Mockito.when(delegate.permissions()).thenReturn(delegatePermissions);

		CryptoPosixFileAttributes attrs = new CryptoPosixFileAttributes(delegate, FILE,null, cryptor, Optional.of(openCryptoFile), true);
		Assertions.assertArrayEquals(EnumSet.of(OWNER_READ, GROUP_READ, OTHERS_READ, OWNER_EXECUTE, GROUP_EXECUTE, OTHERS_EXECUTE).toArray(), attrs.permissions().toArray());
	}

}
