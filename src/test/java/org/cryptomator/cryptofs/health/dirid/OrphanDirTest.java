package org.cryptomator.cryptofs.health.dirid;

import com.google.common.io.BaseEncoding;
import org.cryptomator.cryptofs.common.Constants;
import org.cryptomator.cryptolib.api.FileNameCryptor;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.Mockito;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.UUID;

public class OrphanDirTest {

	@TempDir
	public Path pathToVault;

	@Test
	@DisplayName("prepareCryptFileSystem() runs without error on not existing recovery dir")
	public void testPrepareCryptoFileSystemNonExistingRecoveryDir() throws IOException {
		Path p = Mockito.mock(Path.class, "ignored");
		OrphanDir result = new OrphanDir(p);


		Path cipherRootDir = pathToVault.resolve("d/00/0000");
		Files.createDirectories(cipherRootDir);
		String clearStepParentName = "step-parent";
		FileNameCryptor cryptor = Mockito.mock(FileNameCryptor.class);
		Mockito.doReturn("000000").when(cryptor).hashDirectoryId(Constants.ROOT_DIR_ID);
		Mockito.doReturn("111111").when(cryptor).hashDirectoryId(Constants.RECOVERY_DIR_ID);
		Mockito.doReturn("222222").when(cryptor).hashDirectoryId("aaaaaa");

		Mockito.doReturn("1").when(cryptor).encryptFilename(BaseEncoding.base64Url(), Constants.RECOVERY_DIR_NAME, Constants.ROOT_DIR_ID.getBytes(StandardCharsets.UTF_8));
		Mockito.doReturn("2").when(cryptor).encryptFilename(BaseEncoding.base64Url(), clearStepParentName, Constants.RECOVERY_DIR_ID.getBytes(StandardCharsets.UTF_8));

		try (var uuidClass = Mockito.mockStatic(UUID.class)) {
			UUID uuid = Mockito.mock(UUID.class);
			uuidClass.when(() -> UUID.randomUUID()).thenReturn(uuid);
			Mockito.doReturn("aaaaaa").when(uuid).toString();

			result.prepareCryptoFilesystem(pathToVault, cryptor, clearStepParentName);
		}

		Assertions.assertEquals(Constants.RECOVERY_DIR_ID, Files.readString(pathToVault.resolve("d/00/0000/1.c9r/dir.c9r"), StandardCharsets.UTF_8));
		Assertions.assertEquals("aaaaaa", Files.readString(pathToVault.resolve("d/11/1111/2.c9r/dir.c9r"), StandardCharsets.UTF_8));
		Assertions.assertTrue(Files.isDirectory(pathToVault.resolve("d/22/2222")));

	}

	@Test
	@DisplayName("prepareCryptFileSystem() runs without error on existing recovery dir")
	public void testPrepareCryptoFileSystemExistingRecoveryDir() throws IOException {
		Path p = Mockito.mock(Path.class, "ignored");
		OrphanDir result = new OrphanDir(p);

		Path userCreatedRecoveryDirFile = pathToVault.resolve("d/00/0000/1.c9r/dir.c9r");
		Files.createDirectories(userCreatedRecoveryDirFile.getParent());
		Files.writeString(userCreatedRecoveryDirFile, Constants.RECOVERY_DIR_ID, StandardCharsets.UTF_8, StandardOpenOption.TRUNCATE_EXISTING, StandardOpenOption.WRITE, StandardOpenOption.CREATE);

		String clearStepParentName = "step-parent";
		FileNameCryptor cryptor = Mockito.mock(FileNameCryptor.class);
		Mockito.doReturn("000000").when(cryptor).hashDirectoryId(Constants.ROOT_DIR_ID);
		Mockito.doReturn("111111").when(cryptor).hashDirectoryId(Constants.RECOVERY_DIR_ID);
		Mockito.doReturn("222222").when(cryptor).hashDirectoryId("aaaaaa");

		Mockito.doReturn("1").when(cryptor).encryptFilename(BaseEncoding.base64Url(), Constants.RECOVERY_DIR_NAME, Constants.ROOT_DIR_ID.getBytes(StandardCharsets.UTF_8));
		Mockito.doReturn("2").when(cryptor).encryptFilename(BaseEncoding.base64Url(), clearStepParentName, Constants.RECOVERY_DIR_ID.getBytes(StandardCharsets.UTF_8));

		try (var uuidClass = Mockito.mockStatic(UUID.class)) {
			UUID uuid = Mockito.mock(UUID.class);
			uuidClass.when(() -> UUID.randomUUID()).thenReturn(uuid);
			Mockito.doReturn("aaaaaa").when(uuid).toString();

			result.prepareCryptoFilesystem(pathToVault, cryptor, clearStepParentName);
		}

		Assertions.assertEquals(Constants.RECOVERY_DIR_ID, Files.readString(pathToVault.resolve("d/00/0000/1.c9r/dir.c9r"), StandardCharsets.UTF_8));
		Assertions.assertEquals("aaaaaa", Files.readString(pathToVault.resolve("d/11/1111/2.c9r/dir.c9r"), StandardCharsets.UTF_8));
		Assertions.assertTrue(Files.isDirectory(pathToVault.resolve("d/22/2222")));
	}

	@Test
	@DisplayName("prepareCryptFileSystem() throws exception on existing recovery dir with wrong id")
	public void testPrepareCryptoFSWithWrongRecoveryDir() throws IOException {
		Path p = Mockito.mock(Path.class, "ignored");
		OrphanDir result = new OrphanDir(p);

		Path userCreatedRecoveryDirFile = pathToVault.resolve("d/00/0000/1.c9r/dir.c9r");
		Files.createDirectories(userCreatedRecoveryDirFile.getParent());
		Files.writeString(userCreatedRecoveryDirFile, UUID.randomUUID().toString(), StandardCharsets.UTF_8, StandardOpenOption.TRUNCATE_EXISTING, StandardOpenOption.WRITE, StandardOpenOption.CREATE);

		String clearStepParentName = "step-parent";
		FileNameCryptor cryptor = Mockito.mock(FileNameCryptor.class);
		Mockito.doReturn("000000").when(cryptor).hashDirectoryId(Constants.ROOT_DIR_ID);
		Mockito.doReturn("111111").when(cryptor).hashDirectoryId(Constants.RECOVERY_DIR_ID);
		Mockito.doReturn("222222").when(cryptor).hashDirectoryId("aaaaaa");

		Mockito.doReturn("1").when(cryptor).encryptFilename(BaseEncoding.base64Url(), Constants.RECOVERY_DIR_NAME, Constants.ROOT_DIR_ID.getBytes(StandardCharsets.UTF_8));
		Mockito.doReturn("2").when(cryptor).encryptFilename(BaseEncoding.base64Url(), clearStepParentName, Constants.RECOVERY_DIR_ID.getBytes(StandardCharsets.UTF_8));

		try (var uuidClass = Mockito.mockStatic(UUID.class)) {
			UUID uuid = Mockito.mock(UUID.class);
			uuidClass.when(() -> UUID.randomUUID()).thenReturn(uuid);
			Mockito.doReturn("aaaaaa").when(uuid).toString();

			Assertions.assertThrows(FileAlreadyExistsException.class, () -> result.prepareCryptoFilesystem(pathToVault, cryptor, clearStepParentName));
		}

		Assertions.assertNotEquals(Constants.RECOVERY_DIR_ID, Files.readString(pathToVault.resolve("d/00/0000/1.c9r/dir.c9r"), StandardCharsets.UTF_8));
		Assertions.assertTrue(Files.notExists(pathToVault.resolve("d/11/1111/2.c9r/dir.c9r")));
		Assertions.assertTrue(Files.notExists(pathToVault.resolve("d/22/2222")));

	}
}
