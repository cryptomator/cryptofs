package org.cryptomator.cryptofs.health.dirid;

import com.google.common.io.BaseEncoding;
import org.cryptomator.cryptofs.CryptoPathMapper;
import org.cryptomator.cryptofs.common.Constants;
import org.cryptomator.cryptolib.api.FileNameCryptor;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
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
import java.security.MessageDigest;
import java.util.UUID;

public class OrphanDirTest {

	@TempDir
	public Path pathToVault;

	private OrphanDir result;
	private Path dataDir;
	private Path cipherRoot;
	private Path cipherOrphan;
	private FileNameCryptor cryptor;

	@BeforeEach
	public void init() throws IOException {
		Path p = Mockito.mock(Path.class, "ignored");
		result = new OrphanDir(p);

		dataDir = pathToVault.resolve("d");
		cipherRoot = dataDir.resolve("00/0000");
		cipherOrphan = dataDir.resolve("33/3333");

		Files.createDirectories(cipherRoot);
		Files.createDirectories(cipherOrphan);

		cryptor = Mockito.mock(FileNameCryptor.class);
	}

	@Test
	@DisplayName("prepareCryptFileSystem() runs without error on not existing recovery dir")
	public void testPrepareCryptoFileSystemNonExistingRecoveryDir() throws IOException {
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
		Path existingRecoveryDirFile = cipherRoot.resolve("1.c9r/dir.c9r");
		Files.createDirectories(existingRecoveryDirFile.getParent());
		Files.writeString(existingRecoveryDirFile, Constants.RECOVERY_DIR_ID, StandardCharsets.UTF_8, StandardOpenOption.TRUNCATE_EXISTING, StandardOpenOption.WRITE, StandardOpenOption.CREATE);

		String clearStepParentName = "step-parent";
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
		Path existingRecoveryDirFile = cipherRoot.resolve("1.c9r/dir.c9r");
		Files.createDirectories(existingRecoveryDirFile.getParent());
		Files.writeString(existingRecoveryDirFile, UUID.randomUUID().toString(), StandardCharsets.UTF_8, StandardOpenOption.TRUNCATE_EXISTING, StandardOpenOption.WRITE, StandardOpenOption.CREATE);

		String clearStepParentName = "step-parent";
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

	@Test
	@DisplayName("adoptOrphanedResource runs for unshortened resource")
	public void testAdoptOrphanedUnshortened() throws IOException {
		String expectedMsg = "Please, sir, I want some more.";
		OrphanDir.Adoption adoption = new OrphanDir.Adoption("OliverTwist", cipherOrphan.resolve("orphan.c9r"));
		Files.writeString(adoption.oldCipherPath(), expectedMsg, StandardCharsets.UTF_8, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE);

		CryptoPathMapper.CiphertextDirectory stepParentDir = new CryptoPathMapper.CiphertextDirectory("aaaaaa", pathToVault.resolve("d/22/2222"));
		Files.createDirectories(stepParentDir.path);

		Mockito.doReturn("adopted").when(cryptor).encryptFilename(BaseEncoding.base64Url(), adoption.newClearname(), stepParentDir.dirId.getBytes(StandardCharsets.UTF_8));

		result.adoptOrphanedResource(adoption, stepParentDir, cryptor, "longNameSuffix");

		Assertions.assertEquals(expectedMsg, Files.readString(stepParentDir.path.resolve("adopted.c9r")));
		Assertions.assertTrue(Files.notExists(adoption.oldCipherPath()));
	}

	@Test
	@DisplayName("adoptOrphanedResource runs for shortened resource with existing name.c9s")
	public void testAdoptOrphanedShortened() throws IOException {
		Path orphanDir = pathToVault.resolve("d/33/3333/");
		OrphanDir.Adoption adoption = new OrphanDir.Adoption("Jim Knopf", orphanDir.resolve("orphan.c9s"));
		Files.createDirectories(adoption.oldCipherPath());
		Files.createFile(adoption.oldCipherPath().resolve("name.c9s"));

		CryptoPathMapper.CiphertextDirectory stepParentDir = new CryptoPathMapper.CiphertextDirectory("aaaaaa", pathToVault.resolve("d/22/2222"));
		Files.createDirectories(stepParentDir.path);

		Mockito.doReturn("adopted").when(cryptor).encryptFilename(Mockito.any(), Mockito.any(), Mockito.any());
		try (var messageDigestClass = Mockito.mockStatic(MessageDigest.class); //
			 var baseEncodingClass = Mockito.mockStatic(BaseEncoding.class)) {
			MessageDigest sha1 = Mockito.mock(MessageDigest.class);
			messageDigestClass.when(() -> MessageDigest.getInstance("SHA1")).thenReturn(sha1);
			Mockito.doReturn(new byte[]{}).when(sha1).digest(Mockito.any());

			BaseEncoding base64url = Mockito.mock(BaseEncoding.class);
			baseEncodingClass.when(() -> BaseEncoding.base64Url()).thenReturn(base64url);
			Mockito.doReturn("adopted_shortened").when(base64url).encode(Mockito.any());

			result.adoptOrphanedResource(adoption, stepParentDir, cryptor, "");
		}

		Assertions.assertTrue(Files.exists(stepParentDir.path.resolve("adopted_shortened.c9s")));
		Assertions.assertEquals("adopted.c9r", Files.readString(stepParentDir.path.resolve("adopted_shortened.c9s/name.c9s")));
		Assertions.assertTrue(Files.notExists(adoption.oldCipherPath()));
	}


	@Test
	@DisplayName("adoptOrphanedResource runs for shortened resource without existing name.c9s")
	public void testAdoptOrphanedShortenedMissingNameC9s() throws IOException {
		Path orphanDir = pathToVault.resolve("d/33/3333/");
		OrphanDir.Adoption adoption = new OrphanDir.Adoption("Tom Sawyer", orphanDir.resolve("orphan.c9s"));
		Files.createDirectories(adoption.oldCipherPath());

		CryptoPathMapper.CiphertextDirectory stepParentDir = new CryptoPathMapper.CiphertextDirectory("aaaaaa", pathToVault.resolve("d/22/2222"));
		Files.createDirectories(stepParentDir.path);

		Mockito.doReturn("adopted").when(cryptor).encryptFilename(Mockito.any(), Mockito.any(), Mockito.any());
		try (var messageDigestClass = Mockito.mockStatic(MessageDigest.class); //
			 var baseEncodingClass = Mockito.mockStatic(BaseEncoding.class)) {
			MessageDigest sha1 = Mockito.mock(MessageDigest.class);
			messageDigestClass.when(() -> MessageDigest.getInstance("SHA1")).thenReturn(sha1);
			Mockito.doReturn(new byte[]{}).when(sha1).digest(Mockito.any());

			BaseEncoding base64url = Mockito.mock(BaseEncoding.class);
			baseEncodingClass.when(() -> BaseEncoding.base64Url()).thenReturn(base64url);
			Mockito.doReturn("adopted_shortened").when(base64url).encode(Mockito.any());

			result.adoptOrphanedResource(adoption, stepParentDir, cryptor, "");
		}

		Assertions.assertTrue(Files.exists(stepParentDir.path.resolve("adopted_shortened.c9s")));
		Assertions.assertEquals("adopted.c9r", Files.readString(stepParentDir.path.resolve("adopted_shortened.c9s/name.c9s")));
		Assertions.assertTrue(Files.notExists(adoption.oldCipherPath()));
	}
}
