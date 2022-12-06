package org.cryptomator.cryptofs.health.dirid;

import com.google.common.io.BaseEncoding;
import org.cryptomator.cryptofs.CryptoPathMapper;
import org.cryptomator.cryptofs.DirectoryIdBackup;
import org.cryptomator.cryptofs.VaultConfig;
import org.cryptomator.cryptofs.common.Constants;
import org.cryptomator.cryptolib.api.AuthenticationFailedException;
import org.cryptomator.cryptolib.api.Cryptor;
import org.cryptomator.cryptolib.api.FileNameCryptor;
import org.cryptomator.cryptolib.api.Masterkey;
import org.cryptomator.cryptolib.common.DecryptingReadableByteChannel;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.Mockito;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.ReadableByteChannel;
import java.nio.channels.SeekableByteChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

public class OrphanDirTest {

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
		Path p = Mockito.mock(Path.class, "ignored");
		result = new OrphanContentDir(p);

		dataDir = pathToVault.resolve("d");
		cipherRoot = dataDir.resolve("00/0000");
		cipherRecovery = dataDir.resolve("11/1111");
		cipherOrphan = dataDir.resolve("33/3333");
		Files.createDirectories(cipherRoot);
		Files.createDirectories(cipherOrphan);

		cryptor = Mockito.mock(Cryptor.class);
		fileNameCryptor = Mockito.mock(FileNameCryptor.class);
		Mockito.doReturn(fileNameCryptor).when(cryptor).fileNameCryptor();
		Mockito.doReturn(fileNameCryptor).when(cryptor).fileNameCryptor();
	}

	@Test
	@DisplayName("OrphanDir result has a fix")
	public void testGetFix() {
		Assertions.assertTrue(result.getFix(Mockito.mock(Path.class), Mockito.mock(VaultConfig.class), Mockito.mock(Masterkey.class), Mockito.mock(Cryptor.class)).isPresent());
	}


	@Nested
	class PrepareRecoveryDirTests {

		@BeforeEach
		public void init() {
			Mockito.doReturn("000000").when(fileNameCryptor).hashDirectoryId(Constants.ROOT_DIR_ID);
			Mockito.doReturn("111111").when(fileNameCryptor).hashDirectoryId(Constants.RECOVERY_DIR_ID);
			Mockito.doReturn("222222").when(fileNameCryptor).hashDirectoryId("aaaaaa");

			Mockito.doReturn("1").when(fileNameCryptor).encryptFilename(BaseEncoding.base64Url(), Constants.RECOVERY_DIR_NAME, Constants.ROOT_DIR_ID.getBytes(StandardCharsets.UTF_8));
		}


		@Test
		@DisplayName("prepareRecoveryDir() creates recovery dir if not existent")
		public void testPrepareStepParentNonExistingRecoveryDir() throws IOException {
			Path actualCipherDir = result.prepareRecoveryDir(pathToVault, fileNameCryptor);

			Assertions.assertEquals(cipherRecovery, actualCipherDir);
			Assertions.assertEquals(Constants.RECOVERY_DIR_ID, Files.readString(pathToVault.resolve("d/00/0000/1.c9r/dir.c9r"), StandardCharsets.UTF_8));
			Assertions.assertTrue(Files.exists(cipherRecovery));
		}


		@Test
		@DisplayName("prepareRecoveryDir() runs without error on existing recovery dir")
		public void testPrepareStepParentExistingRecoveryDir() throws IOException {
			Path existingRecoveryDirFile = cipherRoot.resolve("1.c9r/dir.c9r");
			Files.createDirectories(existingRecoveryDirFile.getParent());
			Files.writeString(existingRecoveryDirFile, Constants.RECOVERY_DIR_ID, StandardCharsets.UTF_8, StandardOpenOption.TRUNCATE_EXISTING, StandardOpenOption.WRITE, StandardOpenOption.CREATE);
			Files.createDirectories(cipherRecovery);

			Path actualCipherDir = result.prepareRecoveryDir(pathToVault, fileNameCryptor);

			Assertions.assertEquals(cipherRecovery, actualCipherDir);
			Assertions.assertEquals(Constants.RECOVERY_DIR_ID, Files.readString(pathToVault.resolve("d/00/0000/1.c9r/dir.c9r"), StandardCharsets.UTF_8));
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
			Assertions.assertEquals(Constants.RECOVERY_DIR_ID, Files.readString(pathToVault.resolve("d/00/0000/1.c9r/dir.c9r"), StandardCharsets.UTF_8));
			Assertions.assertTrue(Files.isDirectory(cipherRecovery));
		}


		@Test
		@DisplayName("prepareRecoveryDir() throws exception on existing recovery dir with wrong id")
		public void testPrepareStepParentWithWrongRecoveryDir() throws IOException {
			Path existingRecoveryDirFile = cipherRoot.resolve("1.c9r/dir.c9r");
			Files.createDirectories(existingRecoveryDirFile.getParent());
			Files.writeString(existingRecoveryDirFile, UUID.randomUUID().toString(), StandardCharsets.UTF_8, StandardOpenOption.TRUNCATE_EXISTING, StandardOpenOption.WRITE, StandardOpenOption.CREATE);

			Assertions.assertThrows(FileAlreadyExistsException.class, () -> result.prepareRecoveryDir(pathToVault, fileNameCryptor));

			Assertions.assertNotEquals(Constants.RECOVERY_DIR_ID, Files.readString(existingRecoveryDirFile, StandardCharsets.UTF_8));
		}
	}


	@Nested
	class PrepareStepParentTests {

		private String clearStepParentName;

		@BeforeEach
		public void init() throws IOException {
			clearStepParentName = "step-parent";
			Files.createDirectories(cipherRecovery);

			Mockito.doReturn("222222").when(fileNameCryptor).hashDirectoryId("aaaaaa");
			Mockito.doReturn("1").when(fileNameCryptor).encryptFilename(BaseEncoding.base64Url(), Constants.RECOVERY_DIR_NAME, Constants.ROOT_DIR_ID.getBytes(StandardCharsets.UTF_8));
			Mockito.doReturn("2").when(fileNameCryptor).encryptFilename(BaseEncoding.base64Url(), clearStepParentName, Constants.RECOVERY_DIR_ID.getBytes(StandardCharsets.UTF_8));
		}

		@Test
		@DisplayName("prepareStepParent() runs without error on not-existing stepparent")
		public void testPrepareStepParent() throws IOException {
			try (var uuidClass = Mockito.mockStatic(UUID.class); //
				 var dirIdBackupClass = Mockito.mockStatic(DirectoryIdBackup.class)) {
				UUID uuid = Mockito.mock(UUID.class);
				uuidClass.when(UUID::randomUUID).thenReturn(uuid);
				Mockito.doReturn("aaaaaa").when(uuid).toString();
				dirIdBackupClass.when(() -> DirectoryIdBackup.backupManually(Mockito.eq(cryptor), Mockito.any())).thenAnswer(invocation -> null);

				result.prepareStepParent(dataDir, cipherRecovery, cryptor, clearStepParentName);

				dirIdBackupClass.verify(() -> DirectoryIdBackup.backupManually(Mockito.eq(cryptor), Mockito.any()), Mockito.times(1));
			}
			Assertions.assertEquals("aaaaaa", Files.readString(cipherRecovery.resolve("2.c9r/dir.c9r"), StandardCharsets.UTF_8));
			Assertions.assertTrue(Files.isDirectory(pathToVault.resolve("d/22/2222")));
		}

		@Test
		@DisplayName("prepareStepParent() runs without error on existing stepparent")
		public void testPrepareStepParentExistingStepParentDir() throws IOException {
			Path existingStepparentDirFile = cipherRecovery.resolve("2.c9r/dir.c9r");
			Files.createDirectories(existingStepparentDirFile.getParent());
			Files.writeString(existingStepparentDirFile, "aaaaaa", StandardCharsets.UTF_8, StandardOpenOption.TRUNCATE_EXISTING, StandardOpenOption.WRITE, StandardOpenOption.CREATE);
			Path cipherStepparent = dataDir.resolve("22/2222");
			Files.createDirectories(cipherStepparent);

			try (var uuidClass = Mockito.mockStatic(UUID.class); //
				 var dirIdBackupClass = Mockito.mockStatic(DirectoryIdBackup.class)) {
				UUID uuid = Mockito.mock(UUID.class);
				uuidClass.when(UUID::randomUUID).thenReturn(uuid);
				Mockito.doReturn("aaaaaa").when(uuid).toString();
				dirIdBackupClass.when(() -> DirectoryIdBackup.backupManually(Mockito.eq(cryptor), Mockito.any())).thenThrow(new FileAlreadyExistsException("dirId file exists"));

				result.prepareStepParent(dataDir, cipherRecovery, cryptor, clearStepParentName);

				dirIdBackupClass.verify(() -> DirectoryIdBackup.backupManually(Mockito.eq(cryptor), Mockito.any()), Mockito.times(1));
			}
			Assertions.assertEquals("aaaaaa", Files.readString(cipherRecovery.resolve("2.c9r/dir.c9r"), StandardCharsets.UTF_8));
			Assertions.assertTrue(Files.isDirectory(pathToVault.resolve("d/22/2222")));
		}


		@Test
		@DisplayName("prepareStepParent() runs without error on orphaned stepparent")
		public void testPrepareStepParentOrphanedStepParentDir() throws IOException {
			Path missingStepparentDirFile = cipherRecovery.resolve("2.c9r/dir.c9r");
			Files.createDirectories(missingStepparentDirFile.getParent());
			Path cipherStepparent = dataDir.resolve("22/2222");
			Files.createDirectories(cipherStepparent);

			try (var uuidClass = Mockito.mockStatic(UUID.class); //
				 var dirIdBackupClass = Mockito.mockStatic(DirectoryIdBackup.class)) {
				UUID uuid = Mockito.mock(UUID.class);
				uuidClass.when(UUID::randomUUID).thenReturn(uuid);
				Mockito.doReturn("aaaaaa").when(uuid).toString();
				dirIdBackupClass.when(() -> DirectoryIdBackup.backupManually(Mockito.eq(cryptor), Mockito.any())).thenAnswer(invocation -> null);

				result.prepareStepParent(dataDir, cipherRecovery, cryptor, clearStepParentName);

				dirIdBackupClass.verify(() -> DirectoryIdBackup.backupManually(Mockito.eq(cryptor), Mockito.any()), Mockito.times(1));
			}
			Assertions.assertEquals("aaaaaa", Files.readString(cipherRecovery.resolve("2.c9r/dir.c9r"), StandardCharsets.UTF_8));
			Assertions.assertTrue(Files.isDirectory(pathToVault.resolve("d/22/2222")));
		}
	}


	@Nested
	class RetrieveDirIdTests {

		private OrphanContentDir resultSpy;

		@BeforeEach
		public void init() {
			resultSpy = Mockito.spy(result);
		}

		@Test
		@DisplayName("retrieveDirId extracts directory id of cipher-dir/dirId.c9r")
		public void testRetrieveDirIdSuccess() throws IOException {
			var dirIdFile = cipherOrphan.resolve(Constants.DIR_BACKUP_FILE_NAME);
			var dirId = "random-uuid-with-at-most-36chars";

			Files.writeString(dirIdFile, dirId, StandardCharsets.US_ASCII, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE);
			DecryptingReadableByteChannel dirIdReadChannel = Mockito.mock(DecryptingReadableByteChannel.class);

			Mockito.doReturn(dirIdReadChannel).when(resultSpy).createDecryptingReadableByteChannel(Mockito.any(), Mockito.eq(cryptor));
			AtomicInteger readBytesInMockedChannel = new AtomicInteger(0);
			//in every invocation the channel position is updated, simulating a stateful channel
			Mockito.doAnswer(invocationOnMock -> {
				ByteBuffer buf = invocationOnMock.getArgument(0);
				try (SeekableByteChannel channel = Files.newByteChannel(dirIdFile, StandardOpenOption.READ)) {
					channel.position(readBytesInMockedChannel.get());
					readBytesInMockedChannel.getAndSet(channel.read(buf));
					return readBytesInMockedChannel.get();
				}
			}).when(dirIdReadChannel).read(Mockito.any());

			Mockito.when(fileNameCryptor.hashDirectoryId(dirId)).thenReturn("333333");

			var maybeDirId = resultSpy.retrieveDirId(cipherOrphan, cryptor);

			Assertions.assertTrue(maybeDirId.isPresent());
			Assertions.assertEquals(dirId, maybeDirId.get());
		}

		@Test
		@DisplayName("retrieveDirId returns an empty optional if cipher-dir/dirId.c9r cannot be read")
		public void testRetrieveDirIdIOExceptionReadingFile() throws IOException {
			var notExistingResult = resultSpy.retrieveDirId(cipherOrphan, cryptor);

			Assertions.assertTrue(notExistingResult.isEmpty());
		}

	}


	@Nested
	class RestoreFilenameTests {

		@Test
		@DisplayName("restoring filename of not-shortened resource is successful")
		void testRestoreFilenameNormalSuccess() throws IOException {
			Path oldCipherPath = cipherOrphan.resolve("orphan.c9r");
			Files.createFile(oldCipherPath);
			//by using Mockito.eq() in filename parameter Mockito.verfiy() not necessary
			Mockito.when(fileNameCryptor.decryptFilename(Mockito.any(), Mockito.eq("orphan"), Mockito.any())).thenReturn("theTrueName.txt");

			String decryptedFile = result.decryptFileName(oldCipherPath, false, "someDirId", fileNameCryptor);

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
			//by using Mockito.eq() in filename parameter Mockito.verfiy() not necessary
			Mockito.when(fileNameCryptor.decryptFilename(Mockito.any(), Mockito.eq("OrphanWithLongestName"), Mockito.any())).thenReturn("theRealLongName.txt");

			String decryptedFile = result.decryptFileName(oldCipherPath, true, "someDirId", fileNameCryptor);

			Assertions.assertEquals("theRealLongName.txt", decryptedFile);
		}

		@Test
		@DisplayName("restoreFilename with shortened resource throws IO exception when name.c9s cannot be read")
		void testRestoreFilenameShortenedIOException() throws IOException {
			Path oldCipherPath = cipherOrphan.resolve("hashOfOrphanWithLongestName.c9r");
			Files.createDirectory(oldCipherPath);

			Assertions.assertThrows(IOException.class, () -> result.decryptFileName(oldCipherPath, true, "someDirId", fileNameCryptor));
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
			Files.writeString(oldCipherPath, expectedMsg, StandardCharsets.UTF_8, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE);

			CryptoPathMapper.CiphertextDirectory stepParentDir = new CryptoPathMapper.CiphertextDirectory("aaaaaa", pathToVault.resolve("d/22/2222"));
			Files.createDirectories(stepParentDir.path);

			Mockito.doReturn("adopted").when(fileNameCryptor).encryptFilename(BaseEncoding.base64Url(), newClearName, stepParentDir.dirId.getBytes(StandardCharsets.UTF_8));
			var sha1 = Mockito.mock(MessageDigest.class);

			result.adoptOrphanedResource(oldCipherPath, newClearName, false, stepParentDir, fileNameCryptor, sha1);

			Assertions.assertEquals(expectedMsg, Files.readString(stepParentDir.path.resolve("adopted.c9r")));
			Assertions.assertTrue(Files.notExists(oldCipherPath));
		}


		@Test
		@DisplayName("adoptOrphanedResource runs for shortened resource with existing name.c9s")
		public void testAdoptOrphanedShortened() throws IOException {
			Path oldCipherPath = cipherOrphan.resolve("orphan.c9s");
			String newClearName = "JimKnopf";
			Files.createDirectories(oldCipherPath);
			Files.createFile(oldCipherPath.resolve("name.c9s"));

			CryptoPathMapper.CiphertextDirectory stepParentDir = new CryptoPathMapper.CiphertextDirectory("aaaaaa", pathToVault.resolve("d/22/2222"));
			Files.createDirectories(stepParentDir.path);

			Mockito.doReturn("adopted").when(fileNameCryptor).encryptFilename(Mockito.any(), Mockito.any(), Mockito.any());
			try (var baseEncodingClass = Mockito.mockStatic(BaseEncoding.class)) {
				MessageDigest sha1 = Mockito.mock(MessageDigest.class);
				Mockito.doReturn(new byte[]{}).when(sha1).digest(Mockito.any());

				BaseEncoding base64url = Mockito.mock(BaseEncoding.class);
				baseEncodingClass.when(BaseEncoding::base64Url).thenReturn(base64url);
				Mockito.doReturn("adopted_shortened").when(base64url).encode(Mockito.any());

				result.adoptOrphanedResource(oldCipherPath, newClearName, true, stepParentDir, fileNameCryptor, sha1);
			}

			Assertions.assertTrue(Files.exists(stepParentDir.path.resolve("adopted_shortened.c9s")));
			Assertions.assertEquals("adopted.c9r", Files.readString(stepParentDir.path.resolve("adopted_shortened.c9s/name.c9s")));
			Assertions.assertTrue(Files.notExists(oldCipherPath));
		}


		@Test
		@DisplayName("adoptOrphanedResource runs for shortened resource without existing name.c9s")
		public void testAdoptOrphanedShortenedMissingNameC9s() throws IOException {
			Path oldCipherPath = cipherOrphan.resolve("orphan.c9s");
			String newClearName = "TomSawyer";
			Files.createDirectories(oldCipherPath);

			CryptoPathMapper.CiphertextDirectory stepParentDir = new CryptoPathMapper.CiphertextDirectory("aaaaaa", pathToVault.resolve("d/22/2222"));
			Files.createDirectories(stepParentDir.path);

			Mockito.doReturn("adopted").when(fileNameCryptor).encryptFilename(Mockito.any(), Mockito.any(), Mockito.any());
			try (var baseEncodingClass = Mockito.mockStatic(BaseEncoding.class)) {
				MessageDigest sha1 = Mockito.mock(MessageDigest.class);
				Mockito.doReturn(new byte[]{}).when(sha1).digest(Mockito.any());

				BaseEncoding base64url = Mockito.mock(BaseEncoding.class);
				baseEncodingClass.when(BaseEncoding::base64Url).thenReturn(base64url);
				Mockito.doReturn("adopted_shortened").when(base64url).encode(Mockito.any());

				result.adoptOrphanedResource(oldCipherPath, newClearName, true, stepParentDir, fileNameCryptor, sha1);
			}

			Assertions.assertTrue(Files.exists(stepParentDir.path.resolve("adopted_shortened.c9s")));
			Assertions.assertEquals("adopted.c9r", Files.readString(stepParentDir.path.resolve("adopted_shortened.c9s/name.c9s")));
			Assertions.assertTrue(Files.notExists(oldCipherPath));
		}

	}


	@Test
	@DisplayName("fix() prepares vault, process every resource in orphanDir and deletes orphanDir (dirId not present)")
	public void testFixNoDirId() throws IOException {
		result = new OrphanContentDir(dataDir.relativize(cipherOrphan));
		var resultSpy = Mockito.spy(result);

		Path orphan1 = cipherOrphan.resolve("orphan1_with_at_least_26chars.c9r");
		Path orphan2 = cipherOrphan.resolve("orphan2_with_at_least_26chars.c9s");
		Files.createFile(orphan1);
		Files.createDirectories(orphan2);

		CryptoPathMapper.CiphertextDirectory stepParentDir = new CryptoPathMapper.CiphertextDirectory("aaaaaa", dataDir.resolve("22/2222"));

		VaultConfig config = Mockito.mock(VaultConfig.class);
		Mockito.doReturn(170).when(config).getShorteningThreshold();
		Masterkey masterkey = Mockito.mock(Masterkey.class);

		Mockito.doReturn(cipherRecovery).when(resultSpy).prepareRecoveryDir(pathToVault, fileNameCryptor);
		Mockito.doReturn(stepParentDir).when(resultSpy).prepareStepParent(Mockito.eq(dataDir), Mockito.eq(cipherRecovery), Mockito.eq(cryptor), Mockito.any());
		Mockito.doAnswer(invocationOnMock -> {
			Files.delete((Path) invocationOnMock.getArgument(0));
			return null;
		}).when(resultSpy).adoptOrphanedResource(Mockito.any(), Mockito.any(), Mockito.anyBoolean(), Mockito.eq(stepParentDir), Mockito.eq(fileNameCryptor), Mockito.any());

		resultSpy.fix(pathToVault, config, masterkey, cryptor);

		Mockito.verify(resultSpy, Mockito.times(2)).adoptOrphanedResource(Mockito.any(), Mockito.any(), Mockito.anyBoolean(), Mockito.eq(stepParentDir), Mockito.eq(fileNameCryptor), Mockito.any());
		Assertions.assertTrue(Files.notExists(cipherOrphan));
	}

	@Test
	@DisplayName("fix() does not choke when filename cannot be restored")
	public void testFixContinuesOnNotRecoverableFilename() throws IOException {
		result = new OrphanContentDir(dataDir.relativize(cipherOrphan));
		var resultSpy = Mockito.spy(result);

		Path orphan1 = cipherOrphan.resolve("orphan1_with_at_least_26chars.c9r");
		Path orphan2 = cipherOrphan.resolve("orphan2_with_at_least_26chars.c9s");
		Files.createFile(orphan1);
		Files.createDirectories(orphan2);
		Files.createFile(cipherOrphan.resolve(Constants.DIR_BACKUP_FILE_NAME));

		var dirId = Optional.of("trololo-id");

		CryptoPathMapper.CiphertextDirectory stepParentDir = new CryptoPathMapper.CiphertextDirectory("aaaaaa", dataDir.resolve("22/2222"));

		VaultConfig config = Mockito.mock(VaultConfig.class);
		Mockito.doReturn(170).when(config).getShorteningThreshold();
		Masterkey masterkey = Mockito.mock(Masterkey.class);

		Mockito.doReturn(cipherRecovery).when(resultSpy).prepareRecoveryDir(pathToVault, fileNameCryptor);
		Mockito.doReturn(stepParentDir).when(resultSpy).prepareStepParent(Mockito.eq(dataDir), Mockito.eq(cipherRecovery), Mockito.eq(cryptor), Mockito.any());
		Mockito.doReturn(dirId).when(resultSpy).retrieveDirId(cipherOrphan, cryptor);
		Mockito.doThrow(new IOException("4cc3ss d3n13d")).when(resultSpy).decryptFileName(Mockito.eq(orphan1), Mockito.anyBoolean(), Mockito.eq(dirId.get()), Mockito.eq(fileNameCryptor));
		Mockito.doThrow(new AuthenticationFailedException("d0 y0u kn0w m3")).when(resultSpy).decryptFileName(Mockito.eq(orphan2), Mockito.anyBoolean(), Mockito.eq(dirId.get()), Mockito.eq(fileNameCryptor));
		Mockito.doAnswer(invocationOnMock -> {
			Files.delete((Path) invocationOnMock.getArgument(0));
			return null;
		}).when(resultSpy).adoptOrphanedResource(Mockito.any(), Mockito.any(), Mockito.anyBoolean(), Mockito.eq(stepParentDir), Mockito.eq(fileNameCryptor), Mockito.any());

		resultSpy.fix(pathToVault, config, masterkey, cryptor);

		Mockito.verify(resultSpy, Mockito.times(1)).adoptOrphanedResource(Mockito.eq(orphan1), Mockito.any(), Mockito.anyBoolean(), Mockito.eq(stepParentDir), Mockito.eq(fileNameCryptor), Mockito.any());
		Mockito.verify(resultSpy, Mockito.times(1)).adoptOrphanedResource(Mockito.eq(orphan2), Mockito.any(), Mockito.anyBoolean(), Mockito.eq(stepParentDir), Mockito.eq(fileNameCryptor), Mockito.any());
		Assertions.assertTrue(Files.notExists(cipherOrphan));
	}

	@Test
	@DisplayName("fix() prepares vault, process every resource (except dirId file) in orphanDir and deletes orphanDir (dirId present)")
	public void testFixWithDirId() throws IOException {
		result = new OrphanContentDir(dataDir.relativize(cipherOrphan));
		var resultSpy = Mockito.spy(result);

		var lostName1 = "Brother.sibling";
		Path orphan1 = cipherOrphan.resolve("orphan1_with_at_least_26chars.c9r");
		var lostName2 = "Sister.sibling";
		Path orphan2 = cipherOrphan.resolve("orphan2_with_at_least_26chars.c9s");
		Files.createFile(orphan1);
		Files.createDirectories(orphan2);
		Files.createFile(cipherOrphan.resolve(Constants.DIR_BACKUP_FILE_NAME));

		var dirId = Optional.of("trololo-id");

		CryptoPathMapper.CiphertextDirectory stepParentDir = new CryptoPathMapper.CiphertextDirectory("aaaaaa", dataDir.resolve("22/2222"));

		VaultConfig config = Mockito.mock(VaultConfig.class);
		Mockito.doReturn(170).when(config).getShorteningThreshold();
		Masterkey masterkey = Mockito.mock(Masterkey.class);

		Mockito.doReturn(cipherRecovery).when(resultSpy).prepareRecoveryDir(pathToVault, fileNameCryptor);
		Mockito.doReturn(stepParentDir).when(resultSpy).prepareStepParent(Mockito.eq(dataDir), Mockito.eq(cipherRecovery), Mockito.eq(cryptor), Mockito.any());
		Mockito.doReturn(dirId).when(resultSpy).retrieveDirId(cipherOrphan, cryptor);
		Mockito.doReturn(lostName1).when(resultSpy).decryptFileName(Mockito.eq(orphan1), Mockito.anyBoolean(), Mockito.eq(dirId.get()), Mockito.eq(fileNameCryptor));
		Mockito.doReturn(lostName2).when(resultSpy).decryptFileName(Mockito.eq(orphan2), Mockito.anyBoolean(), Mockito.eq(dirId.get()), Mockito.eq(fileNameCryptor));
		Mockito.doAnswer(invocationOnMock -> {
			Path orphanedResource = invocationOnMock.getArgument(0);
			Files.delete(orphanedResource);
			return null;
		}).when(resultSpy).adoptOrphanedResource(Mockito.any(), Mockito.any(), Mockito.anyBoolean(), Mockito.eq(stepParentDir), Mockito.eq(fileNameCryptor), Mockito.any());

		resultSpy.fix(pathToVault, config, masterkey, cryptor);

		Mockito.verify(resultSpy, Mockito.never()).adoptOrphanedResource(Mockito.eq(cipherOrphan.resolve(Constants.DIR_BACKUP_FILE_NAME)), Mockito.any(), Mockito.anyBoolean(), Mockito.eq(stepParentDir), Mockito.eq(fileNameCryptor), Mockito.any());
		Mockito.verify(resultSpy, Mockito.times(1)).adoptOrphanedResource(Mockito.eq(orphan1), Mockito.eq(lostName1), Mockito.anyBoolean(), Mockito.eq(stepParentDir), Mockito.eq(fileNameCryptor), Mockito.any());
		Mockito.verify(resultSpy, Mockito.times(1)).adoptOrphanedResource(Mockito.eq(orphan2), Mockito.eq(lostName2), Mockito.anyBoolean(), Mockito.eq(stepParentDir), Mockito.eq(fileNameCryptor), Mockito.any());
		Assertions.assertTrue(Files.notExists(cipherOrphan));
	}

	@Test
	@DisplayName("fix() prepares vault, process every Cryptomator resource in orphanDir, moves non-Cryptomator resources and deletes orphanDir")
	public void testFixWithNonCryptomatorFiles() throws IOException {
		result = new OrphanContentDir(dataDir.relativize(cipherOrphan));
		var resultSpy = Mockito.spy(result);

		var lostName1 = "Brother.sibling";
		Path orphan1 = cipherOrphan.resolve("orphan1_with_at_least_26chars.c9r");
		var lostName2 = "Sister.sibling";
		Path orphan2 = cipherOrphan.resolve("orphan2_with_at_least_26chars.c9s");
		Path unrelated = cipherOrphan.resolve("unrelated.file");
		Files.createFile(orphan1);
		Files.createDirectories(orphan2);
		Files.createFile(unrelated);
		Files.createFile(cipherOrphan.resolve(Constants.DIR_BACKUP_FILE_NAME));

		var dirId = Optional.of("trololo-id");

		CryptoPathMapper.CiphertextDirectory stepParentDir = new CryptoPathMapper.CiphertextDirectory("aaaaaa", dataDir.resolve("22/2222"));
		Files.createDirectories(stepParentDir.path); //needs to be created here, otherwise the Files.move(non-crypto-resource, stepparent) will fail

		VaultConfig config = Mockito.mock(VaultConfig.class);
		Mockito.doReturn(170).when(config).getShorteningThreshold();
		Masterkey masterkey = Mockito.mock(Masterkey.class);

		Mockito.doReturn(cipherRecovery).when(resultSpy).prepareRecoveryDir(pathToVault, fileNameCryptor);
		Mockito.doReturn(stepParentDir).when(resultSpy).prepareStepParent(Mockito.eq(dataDir), Mockito.eq(cipherRecovery), Mockito.eq(cryptor), Mockito.any());
		Mockito.doReturn(dirId).when(resultSpy).retrieveDirId(cipherOrphan, cryptor);
		Mockito.doReturn(lostName1).when(resultSpy).decryptFileName(Mockito.eq(orphan1), Mockito.anyBoolean(), Mockito.eq(dirId.get()), Mockito.eq(fileNameCryptor));
		Mockito.doReturn(lostName2).when(resultSpy).decryptFileName(Mockito.eq(orphan2), Mockito.anyBoolean(), Mockito.eq(dirId.get()), Mockito.eq(fileNameCryptor));
		Mockito.doAnswer(invocationOnMock -> {
			Path orphanedResource = invocationOnMock.getArgument(0);
			Files.delete(orphanedResource);
			return null;
		}).when(resultSpy).adoptOrphanedResource(Mockito.any(), Mockito.any(), Mockito.anyBoolean(), Mockito.eq(stepParentDir), Mockito.eq(fileNameCryptor), Mockito.any());

		resultSpy.fix(pathToVault, config, masterkey, cryptor);

		Mockito.verify(resultSpy, Mockito.never()).adoptOrphanedResource(Mockito.eq(unrelated), Mockito.any(), Mockito.anyBoolean(), Mockito.eq(stepParentDir), Mockito.eq(fileNameCryptor), Mockito.any());
		Mockito.verify(resultSpy, Mockito.times(1)).adoptOrphanedResource(Mockito.eq(orphan1), Mockito.eq(lostName1), Mockito.anyBoolean(), Mockito.eq(stepParentDir), Mockito.eq(fileNameCryptor), Mockito.any());
		Mockito.verify(resultSpy, Mockito.times(1)).adoptOrphanedResource(Mockito.eq(orphan2), Mockito.eq(lostName2), Mockito.anyBoolean(), Mockito.eq(stepParentDir), Mockito.eq(fileNameCryptor), Mockito.any());
		Assertions.assertTrue(Files.exists(stepParentDir.path.resolve("unrelated.file")));
		Assertions.assertTrue(Files.notExists(cipherOrphan));
	}


	@Test
	@DisplayName("results with same orphan write to same cleartext stepparent")
	public void testFixRepeated() throws IOException {
		VaultConfig config = Mockito.mock(VaultConfig.class);
		Mockito.doReturn(170).when(config).getShorteningThreshold();
		Masterkey masterkey = Mockito.mock(Masterkey.class);

		AtomicReference<String> clearStepparentNameRef = new AtomicReference<>("");

		var interruptedResult = new OrphanContentDir(dataDir.relativize(cipherOrphan));
		var interruptedSpy = Mockito.spy(interruptedResult);
		Mockito.doReturn(cipherRecovery).when(interruptedSpy).prepareRecoveryDir(pathToVault, fileNameCryptor);
		Mockito.doAnswer(invocation -> {
			clearStepparentNameRef.set((String) invocation.getArgument(3));
			throw new IOException("Interrupt");
		}).when(interruptedSpy).prepareStepParent(Mockito.eq(dataDir), Mockito.eq(cipherRecovery), Mockito.eq(cryptor), Mockito.any());

		var continuedResult = new OrphanContentDir(dataDir.relativize(cipherOrphan));
		var continuedSpy = Mockito.spy(continuedResult);
		Mockito.doReturn(cipherRecovery).when(continuedSpy).prepareRecoveryDir(pathToVault, fileNameCryptor);
		Mockito.doThrow(IOException.class).when(continuedSpy).prepareStepParent(Mockito.any(), Mockito.any(), Mockito.any(), Mockito.any());

		Assertions.assertThrows(IOException.class, () -> interruptedSpy.fix(pathToVault, config, masterkey, cryptor));
		Assertions.assertThrows(IOException.class, () -> continuedSpy.fix(pathToVault, config, masterkey, cryptor));

		Mockito.verify(continuedSpy).prepareStepParent(dataDir, cipherRecovery, cryptor, clearStepparentNameRef.get());
	}


	@Test
	@DisplayName("orphaned recovery dir will only be reintegrated")
	public void testFixOrphanedRecoveryDir() throws IOException {
		Path orphanedRecovery = dataDir.resolve("11/1111");
		result = new OrphanContentDir(dataDir.relativize(orphanedRecovery));
		var resultSpy = Mockito.spy(result);

		Path orphan1 = orphanedRecovery.resolve("orphan1.c9r");
		Path orphan2 = orphanedRecovery.resolve("orphan2.c9r");
		Files.createDirectories(orphan1);
		Files.createDirectories(orphan2);


		VaultConfig config = Mockito.mock(VaultConfig.class);
		Mockito.doReturn(170).when(config).getShorteningThreshold();
		Masterkey masterkey = Mockito.mock(Masterkey.class);
		Mockito.doReturn(cipherRecovery).when(resultSpy).prepareRecoveryDir(pathToVault, fileNameCryptor);

		resultSpy.fix(pathToVault, config, masterkey, cryptor);

		Mockito.verify(resultSpy, Mockito.never()).prepareStepParent(Mockito.eq(dataDir), Mockito.eq(cipherRecovery), Mockito.eq(cryptor), Mockito.any());
		Mockito.verify(resultSpy, Mockito.never()).adoptOrphanedResource(Mockito.any(), Mockito.any(), Mockito.anyBoolean(), Mockito.any(), Mockito.eq(fileNameCryptor), Mockito.any());
		Mockito.verify(resultSpy).prepareRecoveryDir(pathToVault, fileNameCryptor);
	}

}
