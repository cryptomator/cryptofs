package org.cryptomator.cryptofs;

import org.cryptomator.cryptofs.common.Constants;
import org.cryptomator.cryptofs.util.TestCryptoException;
import org.cryptomator.cryptolib.api.Cryptor;
import org.cryptomator.cryptolib.api.FileNameCryptor;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mockito;

import java.io.IOException;
import java.nio.file.FileSystemException;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class FileNameDecryptorTest {

	@TempDir
	Path tmpPath;
	Path vaultPath = mock(Path.class);
	DirectoryIdBackup dirIdBackup = mock(DirectoryIdBackup.class);
	LongFileNameProvider longFileNameProvider = mock(LongFileNameProvider.class);
	FileNameCryptor fileNameCryptor = mock(FileNameCryptor.class);
	FileNameDecryptor testObj;
	FileNameDecryptor testObjSpy;

	@BeforeEach
	public void beforeEach() {
		var cryptor = mock(Cryptor.class);
		when(cryptor.fileNameCryptor()).thenReturn(fileNameCryptor);
		testObj = new FileNameDecryptor(vaultPath, cryptor, dirIdBackup, longFileNameProvider);
		testObjSpy = Mockito.spy(testObj);
	}

	@ParameterizedTest
	@DisplayName("Given a ciphertextNode, it's clearname is returned")
	@ValueSource(strings = {Constants.DEFLATED_FILE_SUFFIX, Constants.CRYPTOMATOR_FILE_SUFFIX})
	public void success(String fileExtension) throws IOException {
		var ciphertextNodeNameName = "someFile";
		var ciphertextNode = tmpPath.resolve(ciphertextNodeNameName + fileExtension);
		var dirId = new byte[]{'f', 'o', 'o', 'b', 'a', 'r'};
		var expectedClearName = "veryClearText";
		when(dirIdBackup.read(tmpPath)).thenReturn(dirId);
		when(longFileNameProvider.inflate(ciphertextNode)).thenReturn(ciphertextNodeNameName);
		when(fileNameCryptor.decryptFilename(any(), eq(ciphertextNodeNameName), eq(dirId))).thenReturn(expectedClearName);

		var result = testObjSpy.decryptFilenameInternal(ciphertextNode);
		verify(fileNameCryptor).decryptFilename(any(), eq(ciphertextNodeNameName), eq(dirId));
		Assertions.assertEquals(expectedClearName, result);
	}

	@Test
	@DisplayName("Path is validated before computation")
	public void validatePath() throws IOException {
		var ciphertextNode = tmpPath.resolve("someFile.c9r");
		Mockito.doNothing().when(testObjSpy).validatePath(any());
		Mockito.doReturn("veryClearName").when(testObjSpy).decryptFilenameInternal(any());

		var actual = testObjSpy.decryptFilename(ciphertextNode);
		Assertions.assertEquals("veryClearName", actual);
	}

	@Test
	@DisplayName("If the dirId backup file does not exists, throw UnsupportedOperationException")
	public void notExistingDirIdFile() throws IOException {
		var ciphertextNode = tmpPath.resolve("toDecrypt.c9r");
		when(dirIdBackup.read(tmpPath)).thenThrow(NoSuchFileException.class);

		Assertions.assertThrows(UnsupportedOperationException.class, () -> testObjSpy.decryptFilenameInternal(ciphertextNode));
	}

	@Test
	@DisplayName("If the dirId cannot be read, throw FileSystemException")
	public void notReadableDirIdFile() throws IOException {
		var ciphertextNode = tmpPath.resolve("toDecrypt.c9r");
		when(dirIdBackup.read(tmpPath)) //
				.thenThrow(TestCryptoException.class) //
				.thenThrow(IllegalStateException.class);
		Assertions.assertThrows(FileSystemException.class, () -> testObjSpy.decryptFilenameInternal(ciphertextNode));
		Assertions.assertThrows(FileSystemException.class, () -> testObjSpy.decryptFilenameInternal(ciphertextNode));
	}

	@Test
	@DisplayName("If the ciphertextName cannot be decrypted, throw FileSystemException")
	public void notDecryptableCiphertext() throws IOException {
		var name = "toDecrypt";
		var ciphertextNode = tmpPath.resolve(name + ".c9s");
		var dirId = new byte[]{'f', 'o', 'o', 'b', 'a', 'r'};
		var expectedException = new IOException("Inflation failed");
		when(dirIdBackup.read(tmpPath)).thenReturn(dirId);
		when(longFileNameProvider.inflate(ciphertextNode)).thenThrow(expectedException);

		var actual = Assertions.assertThrows(IOException.class, () -> testObjSpy.decryptFilenameInternal(ciphertextNode));
		Assertions.assertEquals(expectedException, actual);
	}

	@Test
	@DisplayName("If inflating the shortened Name throws exception, it is rethrown")
	public void inflateThrows() throws IOException {
		var name = "toDecrypt";
		var ciphertextNode = tmpPath.resolve(name + ".c9r");
		var dirId = new byte[]{'f', 'o', 'o', 'b', 'a', 'r'};
		when(dirIdBackup.read(tmpPath)).thenReturn(dirId);
		when(fileNameCryptor.decryptFilename(any(), eq(name), eq(dirId))).thenThrow(TestCryptoException.class);

		Assertions.assertThrows(FileSystemException.class, () -> testObjSpy.decryptFilenameInternal(ciphertextNode));
		verify(fileNameCryptor).decryptFilename(any(), eq(name), eq(dirId));
	}

	@Nested
	public class TestValidation {

		Path p = mock(Path.class, "/absolute/path/to/ciphertext.c9r");

		@BeforeEach
		public void beforeEach() {
			doReturn(true).when(testObjSpy).belongsToVault(p);
			doReturn(true).when(testObjSpy).isAtCipherNodeLevel(p);
			doReturn(true).when(testObjSpy).hasCipherNodeExtension(p);
			doReturn(true).when(testObjSpy).hasMinimumFileNameLength(p);
		}

		@Test
		@DisplayName("If node is not part of the vault, validation fails")
		public void validateNotVaultFile() {
			doReturn(false).when(testObjSpy).belongsToVault(p);
			Assertions.assertThrows(IllegalArgumentException.class, () -> testObjSpy.validatePath(p));
			verify(testObjSpy).belongsToVault(any());
		}

		@Test
		@DisplayName("If node is on the wrong level, validation fails")
		public void validateWrongLevel() {
			doReturn(false).when(testObjSpy).isAtCipherNodeLevel(p);
			Assertions.assertThrows(IllegalArgumentException.class, () -> testObjSpy.validatePath(p));
			verify(testObjSpy).isAtCipherNodeLevel(any());
		}


		@Test
		@DisplayName("If node has wrong file extension, validation fails")
		public void validateWrongExtension() {
			doReturn(false).when(testObjSpy).hasCipherNodeExtension(p);
			Assertions.assertThrows(IllegalArgumentException.class, () -> testObjSpy.validatePath(p));
			verify(testObjSpy).hasCipherNodeExtension(any());
		}

		@Test
		@DisplayName("If filename is too short, validation fails")
		public void validateTooShort() {
			doReturn(false).when(testObjSpy).hasMinimumFileNameLength(p);
			Assertions.assertThrows(IllegalArgumentException.class, () -> testObjSpy.validatePath(p));
			verify(testObjSpy).hasMinimumFileNameLength(any());
		}
	}

	@Nested
	public class IsAtCipherNodeLevel {

		@TempDir
		Path tmpDir;

		@Test
		@DisplayName("cipherNodeLevel test requires an absolute path")
		public void requiresAbsolutePath() {
			var relativePath = Path.of("relative/path");
			Assertions.assertThrows(IllegalArgumentException.class, () -> testObj.isAtCipherNodeLevel(relativePath));
		}

		@Test
		public void success() {
			when(vaultPath.getNameCount()).thenReturn(tmpDir.getNameCount());
			var p = tmpDir.resolve("d/AA/BBBBBBBBBBBBBBB/encrypted.file");
			Assertions.assertTrue(testObj.isAtCipherNodeLevel(p));
		}

		@Test
		public void failure() {
			when(vaultPath.getNameCount()).thenReturn(tmpDir.getNameCount());
			var p = tmpDir.resolve("d/AA/other.file");
			Assertions.assertFalse(testObj.isAtCipherNodeLevel(p));
		}
	}

	@ParameterizedTest
	@DisplayName("Only c9r and c9s are accepted file extensions")
	@CsvSource(value = {"file.c9r,true", "file.c9s,true", "filec9r,false", "file.c9l,false",})
	public void testHasCipherNodeExtension(String filename, boolean expected) {
		var p = Path.of(filename);
		var result = testObj.hasCipherNodeExtension(p);
		Assertions.assertEquals(expected, result, "The filename %s is WRONGLY %s".formatted(filename, result ? "accepted" : "rejected"));
	}


}
