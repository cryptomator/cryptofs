package org.cryptomator.cryptofs.health.dirid;

import com.google.common.collect.MoreCollectors;
import com.google.common.io.BaseEncoding;
import org.cryptomator.cryptofs.CiphertextDirectory;
import org.cryptomator.cryptofs.DirectoryIdBackup;
import org.cryptomator.cryptofs.VaultConfig;
import org.cryptomator.cryptofs.common.Constants;
import org.cryptomator.cryptofs.mocks.NullSecureRandom;
import org.cryptomator.cryptofs.util.TestCryptoException;
import org.cryptomator.cryptolib.api.AuthenticationFailedException;
import org.cryptomator.cryptolib.api.Cryptor;
import org.cryptomator.cryptolib.api.CryptorProvider;
import org.cryptomator.cryptolib.api.FileNameCryptor;
import org.cryptomator.cryptolib.api.Masterkey;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.FieldSource;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class OrphanContentDirTest {

	@TempDir
	public Path pathToVault;

	private OrphanContentDir result;
	private Path dataDir;
	private Path cipherRoot;
	private Path cipherRecovery;
	private Path cipherOrphan;
	private Cryptor cryptor;
	private FileNameCryptor fileNameCryptor;

	@BeforeEach
	public void init() throws IOException {
		Path p = mock(Path.class, "ignored");
		result = new OrphanContentDir(p);

		dataDir = pathToVault.resolve("d");
		cipherRoot = dataDir.resolve("00/0000");
		cipherRecovery = dataDir.resolve("11/1111");
		cipherOrphan = dataDir.resolve("33/3333");
		Files.createDirectories(cipherRoot);
		Files.createDirectories(cipherOrphan);

		cryptor = mock(Cryptor.class);
		fileNameCryptor = mock(FileNameCryptor.class);
		doReturn(fileNameCryptor).when(cryptor).fileNameCryptor();
	}

	@Test
	@DisplayName("OrphanDir result has a fix")
	public void testGetFix() {
		Assertions.assertTrue(result.getFix(mock(Path.class), mock(VaultConfig.class), mock(Masterkey.class), mock(Cryptor.class)).isPresent());
	}


	@Nested
	class PrepareRecoveryDirTests {

		@BeforeEach
		public void init() {
			doReturn("000000").when(fileNameCryptor).hashDirectoryId(Constants.ROOT_DIR_ID);
			doReturn("111111").when(fileNameCryptor).hashDirectoryId(Constants.RECOVERY_DIR_ID);
			doReturn("222222").when(fileNameCryptor).hashDirectoryId("aaaaaa");

			doReturn("1").when(fileNameCryptor).encryptFilename(BaseEncoding.base64Url(), Constants.RECOVERY_DIR_NAME, Constants.ROOT_DIR_ID.getBytes(StandardCharsets.UTF_8));
		}


		@Test
		@DisplayName("prepareRecoveryDir() creates recovery dir if not existent")
		public void testPrepareStepParentNonExistingRecoveryDir() throws IOException {
			Path actualCipherDir = result.prepareRecoveryDir(pathToVault, fileNameCryptor);

			Assertions.assertEquals(cipherRecovery, actualCipherDir);
			Assertions.assertEquals(Constants.RECOVERY_DIR_ID, Files.readString(pathToVault.resolve("d/00/0000/1.c9r/dir.c9r")));
			Assertions.assertTrue(Files.exists(cipherRecovery));
		}


		@Test
		@DisplayName("prepareRecoveryDir() runs without error on existing recovery dir")
		public void testPrepareStepParentExistingRecoveryDir() throws IOException {
			Path existingRecoveryDirFile = cipherRoot.resolve("1.c9r/dir.c9r");
			Files.createDirectories(existingRecoveryDirFile.getParent());
			Files.writeString(existingRecoveryDirFile, Constants.RECOVERY_DIR_ID, StandardOpenOption.TRUNCATE_EXISTING, StandardOpenOption.WRITE, StandardOpenOption.CREATE);
			Files.createDirectories(cipherRecovery);

			Path actualCipherDir = result.prepareRecoveryDir(pathToVault, fileNameCryptor);

			Assertions.assertEquals(cipherRecovery, actualCipherDir);
			Assertions.assertEquals(Constants.RECOVERY_DIR_ID, Files.readString(pathToVault.resolve("d/00/0000/1.c9r/dir.c9r")));
			Assertions.assertTrue(Files.isDirectory(cipherRecovery));
		}


		@Test
		@DisplayName("prepareRecoveryDir() simply integrates orphaned recovery dir")
		public void testPrepareStepParentOrphanedRecoveryDir() throws IOException {
			Path missingRecoveryDirFile = cipherRoot.resolve("1.c9r/dir.c9r");
			Files.createDirectories(missingRecoveryDirFile.getParent());
			Files.createDirectories(cipherRecovery);

			Path actualCipherDir = result.prepareRecoveryDir(pathToVault, fileNameCryptor);

			Assertions.assertEquals(cipherRecovery, actualCipherDir);
			Assertions.assertEquals(Constants.RECOVERY_DIR_ID, Files.readString(pathToVault.resolve("d/00/0000/1.c9r/dir.c9r")));
			Assertions.assertTrue(Files.isDirectory(cipherRecovery));
		}


		@Test
		@DisplayName("prepareRecoveryDir() throws exception on existing recovery dir with wrong id")
		public void testPrepareStepParentWithWrongRecoveryDir() throws IOException {
			Path existingRecoveryDirFile = cipherRoot.resolve("1.c9r/dir.c9r");
			Files.createDirectories(existingRecoveryDirFile.getParent());
			Files.writeString(existingRecoveryDirFile, UUID.randomUUID().toString(), StandardOpenOption.TRUNCATE_EXISTING, StandardOpenOption.WRITE, StandardOpenOption.CREATE);

			Assertions.assertThrows(FileAlreadyExistsException.class, () -> result.prepareRecoveryDir(pathToVault, fileNameCryptor));

			Assertions.assertNotEquals(Constants.RECOVERY_DIR_ID, Files.readString(existingRecoveryDirFile));
		}
	}


	@Nested
	class PrepareStepParentTests {

		private String clearStepParentName;

		@BeforeEach
		public void init() throws IOException {
			clearStepParentName = "step-parent";
			Files.createDirectories(cipherRecovery);

			doReturn("222222").when(fileNameCryptor).hashDirectoryId("aaaaaa");
			doReturn("1").when(fileNameCryptor).encryptFilename(BaseEncoding.base64Url(), Constants.RECOVERY_DIR_NAME, Constants.ROOT_DIR_ID.getBytes(StandardCharsets.UTF_8));
			doReturn("2").when(fileNameCryptor).encryptFilename(BaseEncoding.base64Url(), clearStepParentName, Constants.RECOVERY_DIR_ID.getBytes(StandardCharsets.UTF_8));
		}

		@Test
		@DisplayName("prepareStepParent() runs without error on not-existing stepparent")
		public void testPrepareStepParent() throws IOException {
			try (var uuidClass = mockStatic(UUID.class); //
				 var dirIdBackupClass = mockStatic(DirectoryIdBackup.class)) {
				UUID uuid = mock(UUID.class);
				uuidClass.when(UUID::randomUUID).thenReturn(uuid);
				doReturn("aaaaaa").when(uuid).toString();
				dirIdBackupClass.when(() -> DirectoryIdBackup.write(eq(cryptor), any())).thenAnswer(invocation -> null);

				result.prepareStepParent(dataDir, cipherRecovery, cryptor, clearStepParentName);

				dirIdBackupClass.verify(() -> DirectoryIdBackup.write(eq(cryptor), any()), times(1));
			}
			Assertions.assertEquals("aaaaaa", Files.readString(cipherRecovery.resolve("2.c9r/dir.c9r")));
			Assertions.assertTrue(Files.isDirectory(pathToVault.resolve("d/22/2222")));
		}

		@Test
		@DisplayName("prepareStepParent() runs without error on existing stepparent")
		public void testPrepareStepParentExistingStepParentDir() throws IOException {
			Path existingStepparentDirFile = cipherRecovery.resolve("2.c9r/dir.c9r");
			Files.createDirectories(existingStepparentDirFile.getParent());
			Files.writeString(existingStepparentDirFile, "aaaaaa", StandardOpenOption.TRUNCATE_EXISTING, StandardOpenOption.WRITE, StandardOpenOption.CREATE);
			Path cipherStepparent = dataDir.resolve("22/2222");
			Files.createDirectories(cipherStepparent);

			try (var uuidClass = mockStatic(UUID.class); //
				 var dirIdBackupClass = mockStatic(DirectoryIdBackup.class)) {
				UUID uuid = mock(UUID.class);
				uuidClass.when(UUID::randomUUID).thenReturn(uuid);
				doReturn("aaaaaa").when(uuid).toString();
				dirIdBackupClass.when(() -> DirectoryIdBackup.write(eq(cryptor), any())).thenThrow(new FileAlreadyExistsException("dirId file exists"));

				result.prepareStepParent(dataDir, cipherRecovery, cryptor, clearStepParentName);

				dirIdBackupClass.verify(() -> DirectoryIdBackup.write(eq(cryptor), any()), times(1));
			}
			Assertions.assertEquals("aaaaaa", Files.readString(cipherRecovery.resolve("2.c9r/dir.c9r")));
			Assertions.assertTrue(Files.isDirectory(pathToVault.resolve("d/22/2222")));
		}


		@Test
		@DisplayName("prepareStepParent() runs without error on orphaned stepparent")
		public void testPrepareStepParentOrphanedStepParentDir() throws IOException {
			Path missingStepparentDirFile = cipherRecovery.resolve("2.c9r/dir.c9r");
			Files.createDirectories(missingStepparentDirFile.getParent());
			Path cipherStepparent = dataDir.resolve("22/2222");
			Files.createDirectories(cipherStepparent);

			try (var uuidClass = mockStatic(UUID.class); //
				 var dirIdBackupClass = mockStatic(DirectoryIdBackup.class)) {
				UUID uuid = mock(UUID.class);
				uuidClass.when(UUID::randomUUID).thenReturn(uuid);
				doReturn("aaaaaa").when(uuid).toString();
				dirIdBackupClass.when(() -> DirectoryIdBackup.write(eq(cryptor), any())).thenAnswer(invocation -> null);

				result.prepareStepParent(dataDir, cipherRecovery, cryptor, clearStepParentName);

				dirIdBackupClass.verify(() -> DirectoryIdBackup.write(eq(cryptor), any()), times(1));
			}
			Assertions.assertEquals("aaaaaa", Files.readString(cipherRecovery.resolve("2.c9r/dir.c9r")));
			Assertions.assertTrue(Files.isDirectory(pathToVault.resolve("d/22/2222")));
		}
	}


	@Nested
	class RetrieveDirIdTests {

		private OrphanContentDir resultSpy;

		static List<Throwable> expectedExceptions = List.of(new IOException(), new IllegalStateException(), new TestCryptoException());

		@BeforeEach
		public void init() {
			resultSpy = spy(result);
		}

		@Test
		@DisplayName("Successful reading dirId from backup file")
		public void success() {
			var dirId = new byte[]{'f', 'o', 'o'};
			try (var dirIdBackupMock = mockStatic(DirectoryIdBackup.class)) {
				dirIdBackupMock.when(() -> DirectoryIdBackup.read(cryptor, cipherOrphan)).thenReturn(dirId);
				var result = resultSpy.retrieveDirId(cipherOrphan, cryptor);
				Assertions.assertTrue(result.isPresent());
				Assertions.assertArrayEquals(dirId, result.get());
			}
		}

		@ParameterizedTest
		@DisplayName("retrieveDirId returns an empty optional on any exception")
		@FieldSource("expectedExceptions")
		public void testRetrieveDirIdIOExceptionReadingFile(Throwable t) throws IOException {
			try (var dirIdBackupMock = mockStatic(DirectoryIdBackup.class)) {
				dirIdBackupMock.when(() -> DirectoryIdBackup.read(cryptor, cipherOrphan)).thenThrow(t);
				var notExistingResult = resultSpy.retrieveDirId(cipherOrphan, cryptor);
				Assertions.assertTrue(notExistingResult.isEmpty());
			}
		}

	}


	@Nested
	class RestoreFilenameTests {

		@Test
		@DisplayName("restoring filename of not-shortened resource is successful")
		void testRestoreFilenameNormalSuccess() throws IOException {
			Path oldCipherPath = cipherOrphan.resolve("orphan.c9r");
			Files.createFile(oldCipherPath);
			//by using eq() in filename parameter verify() not necessary
			when(fileNameCryptor.decryptFilename(any(), eq("orphan"), any())).thenReturn("theTrueName.txt");

			String decryptedFile = result.decryptFileName(oldCipherPath, false, new byte[]{}, fileNameCryptor);

			Assertions.assertEquals("theTrueName.txt", decryptedFile);
		}

		@Test
		@DisplayName("restoring filename of shortened resource is successful")
		void testRestoreFilenameShortenedSuccess() throws IOException {
			String inflatedEncryptedName = "OrphanWithLongestName.c9r";
			Path oldCipherPath = cipherOrphan.resolve("hashOfOrphanWithLongestName.c9r");
			Path oldCipherPathNameFile = oldCipherPath.resolve(Constants.INFLATED_FILE_NAME);
			Files.createDirectory(oldCipherPath);
			Files.writeString(oldCipherPathNameFile, inflatedEncryptedName);
			//by using eq() in filename parameter verify() not necessary
			when(fileNameCryptor.decryptFilename(any(), eq("OrphanWithLongestName"), any())).thenReturn("theRealLongName.txt");

			String decryptedFile = result.decryptFileName(oldCipherPath, true, new byte[]{}, fileNameCryptor);

			Assertions.assertEquals("theRealLongName.txt", decryptedFile);
		}

		@Test
		@DisplayName("restoreFilename with shortened resource throws IO exception when name.c9s cannot be read")
		void testRestoreFilenameShortenedIOException() throws IOException {
			Path oldCipherPath = cipherOrphan.resolve("hashOfOrphanWithLongestName.c9r");
			Files.createDirectory(oldCipherPath);

			Assertions.assertThrows(IOException.class, () -> result.decryptFileName(oldCipherPath, true, new byte[]{}, fileNameCryptor));
		}
	}


	@Nested
	class AdoptOrphanedTests {

		@Test
		@DisplayName("adoptOrphanedResource runs for unshortened resource")
		public void testAdoptOrphanedUnshortened() throws IOException {
			String expectedMsg = "Please, sir, I want some more.";
			Path oldCipherPath = cipherOrphan.resolve("orphan.c9r");
			String newClearName = "OliverTwist";
			Files.writeString(oldCipherPath, expectedMsg, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE);

			CiphertextDirectory stepParentDir = new CiphertextDirectory("aaaaaa", pathToVault.resolve("d/22/2222"));
			Files.createDirectories(stepParentDir.path());

			doReturn("adopted").when(fileNameCryptor).encryptFilename(BaseEncoding.base64Url(), newClearName, stepParentDir.dirId().getBytes(StandardCharsets.UTF_8));
			var sha1 = mock(MessageDigest.class);

			result.adoptOrphanedResource(oldCipherPath, newClearName, false, stepParentDir, fileNameCryptor, sha1);

			Assertions.assertEquals(expectedMsg, Files.readString(stepParentDir.path().resolve("adopted.c9r")));
			Assertions.assertTrue(Files.notExists(oldCipherPath));
		}


		@Test
		@DisplayName("adoptOrphanedResource runs for shortened resource with existing name.c9s")
		public void testAdoptOrphanedShortened() throws IOException {
			Path oldCipherPath = cipherOrphan.resolve("orphan.c9s");
			String newClearName = "JimKnopf";
			Files.createDirectories(oldCipherPath);
			Files.createFile(oldCipherPath.resolve("name.c9s"));

			CiphertextDirectory stepParentDir = new CiphertextDirectory("aaaaaa", pathToVault.resolve("d/22/2222"));
			Files.createDirectories(stepParentDir.path());

			doReturn("adopted").when(fileNameCryptor).encryptFilename(any(), any(), any());
			try (var baseEncodingClass = mockStatic(BaseEncoding.class)) {
				MessageDigest sha1 = mock(MessageDigest.class);
				doReturn(new byte[]{}).when(sha1).digest(any());

				BaseEncoding base64url = mock(BaseEncoding.class);
				baseEncodingClass.when(BaseEncoding::base64Url).thenReturn(base64url);
				doReturn("adopted_shortened").when(base64url).encode(any());

				result.adoptOrphanedResource(oldCipherPath, newClearName, true, stepParentDir, fileNameCryptor, sha1);
			}

			Assertions.assertTrue(Files.exists(stepParentDir.path().resolve("adopted_shortened.c9s")));
			Assertions.assertEquals("adopted.c9r", Files.readString(stepParentDir.path().resolve("adopted_shortened.c9s/name.c9s")));
			Assertions.assertTrue(Files.notExists(oldCipherPath));
		}


		@Test
		@DisplayName("adoptOrphanedResource runs for shortened resource without existing name.c9s")
		public void testAdoptOrphanedShortenedMissingNameC9s() throws IOException {
			Path oldCipherPath = cipherOrphan.resolve("orphan.c9s");
			String newClearName = "TomSawyer";
			Files.createDirectories(oldCipherPath);

			CiphertextDirectory stepParentDir = new CiphertextDirectory("aaaaaa", pathToVault.resolve("d/22/2222"));
			Files.createDirectories(stepParentDir.path());

			doReturn("adopted").when(fileNameCryptor).encryptFilename(any(), any(), any());
			try (var baseEncodingClass = mockStatic(BaseEncoding.class)) {
				MessageDigest sha1 = mock(MessageDigest.class);
				doReturn(new byte[]{}).when(sha1).digest(any());

				BaseEncoding base64url = mock(BaseEncoding.class);
				baseEncodingClass.when(BaseEncoding::base64Url).thenReturn(base64url);
				doReturn("adopted_shortened").when(base64url).encode(any());

				result.adoptOrphanedResource(oldCipherPath, newClearName, true, stepParentDir, fileNameCryptor, sha1);
			}

			Assertions.assertTrue(Files.exists(stepParentDir.path().resolve("adopted_shortened.c9s")));
			Assertions.assertEquals("adopted.c9r", Files.readString(stepParentDir.path().resolve("adopted_shortened.c9s/name.c9s")));
			Assertions.assertTrue(Files.notExists(oldCipherPath));
		}

	}


	@Test
	@DisplayName("fix() prepares vault, process every resource in orphanDir and deletes orphanDir (dirId not present)")
	public void testFixNoDirId() throws IOException {
		result = new OrphanContentDir(dataDir.relativize(cipherOrphan));
		var resultSpy = spy(result);

		Path orphan1 = cipherOrphan.resolve("orphan1_with_at_least_26chars.c9r");
		Path orphan2 = cipherOrphan.resolve("orphan2_with_at_least_26chars.c9s");
		Files.createFile(orphan1);
		Files.createDirectories(orphan2);

		CiphertextDirectory stepParentDir = new CiphertextDirectory("aaaaaa", dataDir.resolve("22/2222"));

		VaultConfig config = mock(VaultConfig.class);
		doReturn(170).when(config).getShorteningThreshold();
		Masterkey masterkey = mock(Masterkey.class);

		doReturn(cipherRecovery).when(resultSpy).prepareRecoveryDir(pathToVault, fileNameCryptor);
		doReturn(stepParentDir).when(resultSpy).prepareStepParent(eq(dataDir), eq(cipherRecovery), eq(cryptor), any());
		doAnswer(invocationOnMock -> {
			Files.delete((Path) invocationOnMock.getArgument(0));
			return null;
		}).when(resultSpy).adoptOrphanedResource(any(), any(), anyBoolean(), eq(stepParentDir), eq(fileNameCryptor), any());

		try ( var dirIdBackup = mockStatic(DirectoryIdBackup.class)) {
			dirIdBackup.when(() -> DirectoryIdBackup.read(cryptor, cipherOrphan)).thenThrow(IllegalStateException.class);
			resultSpy.fix(pathToVault, config, masterkey, cryptor);
		}


		verify(resultSpy, times(2)).adoptOrphanedResource(any(), any(), anyBoolean(), eq(stepParentDir), eq(fileNameCryptor), any());
		Assertions.assertTrue(Files.notExists(cipherOrphan));
	}

	static List<Integer> shorteningThresholds = List.of(36, 116, 140, 164, 170, 184, 210, 219, 220);

	@ParameterizedTest
	@DisplayName("fix() gives a shortened orphan a ciphertext name exceeding the shortening threshold (dirId not present)")
	@FieldSource("shorteningThresholds")
	public void testFixNoDirIdKeepsShortenedOrphanShortened(int shorteningThreshold) throws IOException {
		result = new OrphanContentDir(dataDir.relativize(cipherOrphan));
		var resultSpy = spy(result);

		Path orphan = cipherOrphan.resolve("orphan_with_at_least_26chars.c9s");
		Files.createDirectories(orphan);

		CiphertextDirectory stepParentDir = new CiphertextDirectory("aaaaaa", dataDir.resolve("22/2222"));
		Files.createDirectories(stepParentDir.path());

		Cryptor realCryptor = CryptorProvider.forScheme(CryptorProvider.Scheme.SIV_GCM).provide(new Masterkey(new byte[64]), NullSecureRandom.INSTANCE);
		var realFileNameCryptor = realCryptor.fileNameCryptor();
		doReturn(realFileNameCryptor).when(cryptor).fileNameCryptor();

		VaultConfig config = mock(VaultConfig.class);
		doReturn(shorteningThreshold).when(config).getShorteningThreshold();
		Masterkey masterkey = mock(Masterkey.class);

		doReturn(cipherRecovery).when(resultSpy).prepareRecoveryDir(pathToVault, realFileNameCryptor);
		doReturn(stepParentDir).when(resultSpy).prepareStepParent(eq(dataDir), eq(cipherRecovery), eq(cryptor), any());

		try (var dirIdBackup = mockStatic(DirectoryIdBackup.class)) {
			dirIdBackup.when(() -> DirectoryIdBackup.read(cryptor, cipherOrphan)).thenThrow(IllegalStateException.class);
			resultSpy.fix(pathToVault, config, masterkey, cryptor);
		}

		try (var adopted = Files.list(stepParentDir.path())) {
			Path adoptedOrphan = adopted.collect(MoreCollectors.onlyElement());
			Assertions.assertTrue(adoptedOrphan.getFileName().toString().endsWith(Constants.DEFLATED_FILE_SUFFIX));
			String cipherName = Files.readString(adoptedOrphan.resolve(Constants.INFLATED_FILE_NAME));
			Assertions.assertTrue(cipherName.length() > shorteningThreshold, () -> "ciphertext name of length " + cipherName.length() + " does not exceed shortening threshold " + shorteningThreshold);
		}
	}

	@Test
	@DisplayName("fix() does not choke when filename cannot be restored")
	public void testFixContinuesOnNotRecoverableFilename() throws IOException {
		result = new OrphanContentDir(dataDir.relativize(cipherOrphan));
		var resultSpy = spy(result);

		Path orphan1 = cipherOrphan.resolve("orphan1_with_at_least_26chars.c9r");
		Path orphan2 = cipherOrphan.resolve("orphan2_with_at_least_26chars.c9s");
		Files.createFile(orphan1);
		Files.createDirectories(orphan2);
		Files.createFile(cipherOrphan.resolve(Constants.DIR_ID_BACKUP_FILE_NAME));

		var dirId = Optional.of(new byte[]{'t', 'r', 'o', 'l', 'o', 'l', 'o'});

		CiphertextDirectory stepParentDir = new CiphertextDirectory("aaaaaa", dataDir.resolve("22/2222"));

		VaultConfig config = mock(VaultConfig.class);
		doReturn(170).when(config).getShorteningThreshold();
		Masterkey masterkey = mock(Masterkey.class);

		doReturn(cipherRecovery).when(resultSpy).prepareRecoveryDir(pathToVault, fileNameCryptor);
		doReturn(stepParentDir).when(resultSpy).prepareStepParent(eq(dataDir), eq(cipherRecovery), eq(cryptor), any());
		doReturn(dirId).when(resultSpy).retrieveDirId(cipherOrphan, cryptor);
		doThrow(new IOException("4cc3ss d3n13d")).when(resultSpy).decryptFileName(eq(orphan1), anyBoolean(), eq(dirId.get()), eq(fileNameCryptor));
		doThrow(new AuthenticationFailedException("d0 y0u kn0w m3")).when(resultSpy).decryptFileName(eq(orphan2), anyBoolean(), eq(dirId.get()), eq(fileNameCryptor));
		doAnswer(invocationOnMock -> {
			Files.delete((Path) invocationOnMock.getArgument(0));
			return null;
		}).when(resultSpy).adoptOrphanedResource(any(), any(), anyBoolean(), eq(stepParentDir), eq(fileNameCryptor), any());

		resultSpy.fix(pathToVault, config, masterkey, cryptor);

		verify(resultSpy, times(1)).adoptOrphanedResource(eq(orphan1), any(), anyBoolean(), eq(stepParentDir), eq(fileNameCryptor), any());
		verify(resultSpy, times(1)).adoptOrphanedResource(eq(orphan2), any(), anyBoolean(), eq(stepParentDir), eq(fileNameCryptor), any());
		Assertions.assertTrue(Files.notExists(cipherOrphan));
	}

	@Test
	@DisplayName("fix() prepares vault, process every resource (except dirId file) in orphanDir and deletes orphanDir (dirId present)")
	public void testFixWithDirId() throws IOException {
		result = new OrphanContentDir(dataDir.relativize(cipherOrphan));
		var resultSpy = spy(result);

		var lostName1 = "Brother.sibling";
		Path orphan1 = cipherOrphan.resolve("orphan1_with_at_least_26chars.c9r");
		var lostName2 = "Sister.sibling";
		Path orphan2 = cipherOrphan.resolve("orphan2_with_at_least_26chars.c9s");
		Files.createFile(orphan1);
		Files.createDirectories(orphan2);
		Files.createFile(cipherOrphan.resolve(Constants.DIR_ID_BACKUP_FILE_NAME));

		var dirId = Optional.of(new byte[]{'t', 'r', 'o', 'l', 'o', 'l', 'o'});

		CiphertextDirectory stepParentDir = new CiphertextDirectory("aaaaaa", dataDir.resolve("22/2222"));

		VaultConfig config = mock(VaultConfig.class);
		doReturn(170).when(config).getShorteningThreshold();
		Masterkey masterkey = mock(Masterkey.class);

		doReturn(cipherRecovery).when(resultSpy).prepareRecoveryDir(pathToVault, fileNameCryptor);
		doReturn(stepParentDir).when(resultSpy).prepareStepParent(eq(dataDir), eq(cipherRecovery), eq(cryptor), any());
		doReturn(dirId).when(resultSpy).retrieveDirId(cipherOrphan, cryptor);
		doReturn(lostName1).when(resultSpy).decryptFileName(eq(orphan1), anyBoolean(), eq(dirId.get()), eq(fileNameCryptor));
		doReturn(lostName2).when(resultSpy).decryptFileName(eq(orphan2), anyBoolean(), eq(dirId.get()), eq(fileNameCryptor));
		doAnswer(invocationOnMock -> {
			Path orphanedResource = invocationOnMock.getArgument(0);
			Files.delete(orphanedResource);
			return null;
		}).when(resultSpy).adoptOrphanedResource(any(), any(), anyBoolean(), eq(stepParentDir), eq(fileNameCryptor), any());

		resultSpy.fix(pathToVault, config, masterkey, cryptor);

		verify(resultSpy, never()).adoptOrphanedResource(eq(cipherOrphan.resolve(Constants.DIR_ID_BACKUP_FILE_NAME)), any(), anyBoolean(), eq(stepParentDir), eq(fileNameCryptor), any());
		verify(resultSpy, times(1)).adoptOrphanedResource(eq(orphan1), eq(lostName1), anyBoolean(), eq(stepParentDir), eq(fileNameCryptor), any());
		verify(resultSpy, times(1)).adoptOrphanedResource(eq(orphan2), eq(lostName2), anyBoolean(), eq(stepParentDir), eq(fileNameCryptor), any());
		Assertions.assertTrue(Files.notExists(cipherOrphan));
	}

	@Test
	@DisplayName("fix() prepares vault, process every Cryptomator resource in orphanDir, moves non-Cryptomator resources and deletes orphanDir")
	public void testFixWithNonCryptomatorFiles() throws IOException {
		result = new OrphanContentDir(dataDir.relativize(cipherOrphan));
		var resultSpy = spy(result);

		var lostName1 = "Brother.sibling";
		Path orphan1 = cipherOrphan.resolve("orphan1_with_at_least_26chars.c9r");
		var lostName2 = "Sister.sibling";
		Path orphan2 = cipherOrphan.resolve("orphan2_with_at_least_26chars.c9s");
		Path unrelated = cipherOrphan.resolve("unrelated.file");
		Files.createFile(orphan1);
		Files.createDirectories(orphan2);
		Files.createFile(unrelated);
		Files.createFile(cipherOrphan.resolve(Constants.DIR_ID_BACKUP_FILE_NAME));

		var dirId = Optional.of(new byte[]{'t', 'r', 'o', 'l', 'o', 'l', 'o'});

		CiphertextDirectory stepParentDir = new CiphertextDirectory("aaaaaa", dataDir.resolve("22/2222"));
		Files.createDirectories(stepParentDir.path()); //needs to be created here, otherwise the Files.move(non-crypto-resource, stepparent) will fail

		VaultConfig config = mock(VaultConfig.class);
		doReturn(170).when(config).getShorteningThreshold();
		Masterkey masterkey = mock(Masterkey.class);

		doReturn(cipherRecovery).when(resultSpy).prepareRecoveryDir(pathToVault, fileNameCryptor);
		doReturn(stepParentDir).when(resultSpy).prepareStepParent(eq(dataDir), eq(cipherRecovery), eq(cryptor), any());
		doReturn(dirId).when(resultSpy).retrieveDirId(cipherOrphan, cryptor);
		doReturn(lostName1).when(resultSpy).decryptFileName(eq(orphan1), anyBoolean(), eq(dirId.get()), eq(fileNameCryptor));
		doReturn(lostName2).when(resultSpy).decryptFileName(eq(orphan2), anyBoolean(), eq(dirId.get()), eq(fileNameCryptor));
		doAnswer(invocationOnMock -> {
			Path orphanedResource = invocationOnMock.getArgument(0);
			Files.delete(orphanedResource);
			return null;
		}).when(resultSpy).adoptOrphanedResource(any(), any(), anyBoolean(), eq(stepParentDir), eq(fileNameCryptor), any());

		resultSpy.fix(pathToVault, config, masterkey, cryptor);

		verify(resultSpy, never()).adoptOrphanedResource(eq(unrelated), any(), anyBoolean(), eq(stepParentDir), eq(fileNameCryptor), any());
		verify(resultSpy, times(1)).adoptOrphanedResource(eq(orphan1), eq(lostName1), anyBoolean(), eq(stepParentDir), eq(fileNameCryptor), any());
		verify(resultSpy, times(1)).adoptOrphanedResource(eq(orphan2), eq(lostName2), anyBoolean(), eq(stepParentDir), eq(fileNameCryptor), any());
		Assertions.assertTrue(Files.exists(stepParentDir.path().resolve("unrelated.file")));
		Assertions.assertTrue(Files.notExists(cipherOrphan));
	}


	@Test
	@DisplayName("results with same orphan write to same cleartext stepparent")
	public void testFixRepeated() throws IOException {
		VaultConfig config = mock(VaultConfig.class);
		doReturn(170).when(config).getShorteningThreshold();
		Masterkey masterkey = mock(Masterkey.class);

		AtomicReference<String> clearStepparentNameRef = new AtomicReference<>("");

		var interruptedResult = new OrphanContentDir(dataDir.relativize(cipherOrphan));
		var interruptedSpy = spy(interruptedResult);
		doReturn(cipherRecovery).when(interruptedSpy).prepareRecoveryDir(pathToVault, fileNameCryptor);
		doAnswer(invocation -> {
			clearStepparentNameRef.set((String) invocation.getArgument(3));
			throw new IOException("Interrupt");
		}).when(interruptedSpy).prepareStepParent(eq(dataDir), eq(cipherRecovery), eq(cryptor), any());

		var continuedResult = new OrphanContentDir(dataDir.relativize(cipherOrphan));
		var continuedSpy = spy(continuedResult);
		doReturn(cipherRecovery).when(continuedSpy).prepareRecoveryDir(pathToVault, fileNameCryptor);
		doThrow(IOException.class).when(continuedSpy).prepareStepParent(any(), any(), any(), any());

		Assertions.assertThrows(IOException.class, () -> interruptedSpy.fix(pathToVault, config, masterkey, cryptor));
		Assertions.assertThrows(IOException.class, () -> continuedSpy.fix(pathToVault, config, masterkey, cryptor));

		verify(continuedSpy).prepareStepParent(dataDir, cipherRecovery, cryptor, clearStepparentNameRef.get());
	}


	@Test
	@DisplayName("orphaned recovery dir will only be reintegrated")
	public void testFixOrphanedRecoveryDir() throws IOException {
		Path orphanedRecovery = dataDir.resolve("11/1111");
		result = new OrphanContentDir(dataDir.relativize(orphanedRecovery));
		var resultSpy = spy(result);

		Path orphan1 = orphanedRecovery.resolve("orphan1.c9r");
		Path orphan2 = orphanedRecovery.resolve("orphan2.c9r");
		Files.createDirectories(orphan1);
		Files.createDirectories(orphan2);


		VaultConfig config = mock(VaultConfig.class);
		doReturn(170).when(config).getShorteningThreshold();
		Masterkey masterkey = mock(Masterkey.class);
		doReturn(cipherRecovery).when(resultSpy).prepareRecoveryDir(pathToVault, fileNameCryptor);

		resultSpy.fix(pathToVault, config, masterkey, cryptor);

		verify(resultSpy, never()).prepareStepParent(eq(dataDir), eq(cipherRecovery), eq(cryptor), any());
		verify(resultSpy, never()).adoptOrphanedResource(any(), any(), anyBoolean(), any(), eq(fileNameCryptor), any());
		verify(resultSpy).prepareRecoveryDir(pathToVault, fileNameCryptor);
	}
}
