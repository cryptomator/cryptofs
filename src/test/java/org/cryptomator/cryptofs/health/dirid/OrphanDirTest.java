package org.cryptomator.cryptofs.health.dirid;

import com.google.common.io.BaseEncoding;
import org.cryptomator.cryptofs.CryptoPathMapper;
import org.cryptomator.cryptofs.VaultConfig;
import org.cryptomator.cryptofs.common.Constants;
import org.cryptomator.cryptolib.api.Cryptor;
import org.cryptomator.cryptolib.api.FileNameCryptor;
import org.cryptomator.cryptolib.api.Masterkey;
import org.cryptomator.cryptolib.common.EncryptingReadableByteChannel;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.Mockito;

import java.io.IOException;
import java.nio.channels.ReadableByteChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;

public class OrphanDirTest {

	@TempDir
	public Path pathToVault;

	private OrphanDir result;
	private Path dataDir;
	private Path cipherRoot;
	private Path cipherRecovery;
	private Path cipherOrphan;
	private Cryptor cryptor;
	private FileNameCryptor fileNameCryptor;

	@BeforeEach
	public void init() throws IOException {
		Path p = Mockito.mock(Path.class, "ignored");
		result = new OrphanDir(p);

		dataDir = pathToVault.resolve("d");
		cipherRoot = dataDir.resolve("00/0000");
		cipherRecovery = dataDir.resolve("11/1111");
		cipherOrphan = dataDir.resolve("33/3333");
		Files.createDirectories(cipherRoot);
		Files.createDirectories(cipherOrphan);

		cryptor = Mockito.mock(Cryptor.class);
		Mockito.doReturn(fileNameCryptor).when(cryptor).fileNameCryptor();
		fileNameCryptor = Mockito.mock(FileNameCryptor.class);
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
			try (var uuidClass = Mockito.mockStatic(UUID.class)) {
				UUID uuid = Mockito.mock(UUID.class);
				uuidClass.when(() -> UUID.randomUUID()).thenReturn(uuid);
				Mockito.doReturn("aaaaaa").when(uuid).toString();

				result.prepareStepParent(dataDir, cipherRecovery, fileNameCryptor, clearStepParentName);
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

			try (var uuidClass = Mockito.mockStatic(UUID.class)) {
				UUID uuid = Mockito.mock(UUID.class);
				uuidClass.when(() -> UUID.randomUUID()).thenReturn(uuid);
				Mockito.doReturn("aaaaaa").when(uuid).toString();

				result.prepareStepParent(dataDir, cipherRecovery, fileNameCryptor, clearStepParentName);
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

			try (var uuidClass = Mockito.mockStatic(UUID.class)) {
				UUID uuid = Mockito.mock(UUID.class);
				uuidClass.when(() -> UUID.randomUUID()).thenReturn(uuid);
				Mockito.doReturn("aaaaaa").when(uuid).toString();

				result.prepareStepParent(dataDir, cipherRecovery, fileNameCryptor, clearStepParentName);
			}

			Assertions.assertEquals("aaaaaa", Files.readString(cipherRecovery.resolve("2.c9r/dir.c9r"), StandardCharsets.UTF_8));
			Assertions.assertTrue(Files.isDirectory(pathToVault.resolve("d/22/2222")));
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

			String decryptedFile = result.restoreFileName(oldCipherPath, false, "someDirId", fileNameCryptor);

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

			String decryptedFile = result.restoreFileName(oldCipherPath, true, "someDirId", fileNameCryptor);

			Assertions.assertEquals("theRealLongName.txt", decryptedFile);
		}

		@Test
		@DisplayName("restoreFilename with shortened resource throws IO exception when name.c9s cannot be read")
		void testRestoreFilenameShortenedIOException() throws IOException {
			Path oldCipherPath = cipherOrphan.resolve("hashOfOrphanWithLongestName.c9r");
			Files.createDirectory(oldCipherPath);

			Assertions.assertThrows(IOException.class, () -> result.restoreFileName(oldCipherPath, true, "someDirId", fileNameCryptor));
		}
	}


	@Nested
	class RetrieveDirIdTests {

		private OrphanDir resultSpy;

		@BeforeEach
		public void init() {
			resultSpy = Mockito.spy(result);
			Mockito.doReturn(fileNameCryptor).when(cryptor).fileNameCryptor();
		}

		@Test
		@DisplayName("retrieveDirId extracts directory id of cipher-dir/dirId.c9r")
		public void testRetrieveDirIdSuccess() throws IOException {
			var dirIdFile = cipherOrphan.resolve(Constants.DIR_ID_FILE);
			var dirId = "random-uuid-with-at-most-36chars";
			Files.writeString(dirIdFile, dirId, StandardCharsets.UTF_8, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE);
			EncryptingReadableByteChannel dirIdReadChannel = Mockito.mock(EncryptingReadableByteChannel.class);

			Mockito.doReturn(dirIdReadChannel).when(resultSpy).wrapDecryptionAround(Mockito.any(), Mockito.eq(cryptor));
			Mockito.doAnswer(invocationOnMock -> {
				try (ReadableByteChannel channel = Files.newByteChannel(dirIdFile, StandardOpenOption.READ)) {
					return channel.read(invocationOnMock.getArgument(0));
				}
			}).when(dirIdReadChannel).read(Mockito.any());

			Mockito.when(fileNameCryptor.hashDirectoryId(Mockito.eq(dirId))).thenReturn("333333");

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


		@Test
		@DisplayName("retrieveDirId returns empty optional if content of dirId.c9r does not match cipher dir hash")
		public void testRetrieveDirIdWrongContent() throws IOException {
			var dirIdFile = cipherOrphan.resolve(Constants.DIR_ID_FILE);
			var dirId = "anOverlyComplexAndCompletelyRandomExampleOfHowAnDirectoryIdIsTooLong";
			Files.writeString(dirIdFile, dirId, StandardCharsets.UTF_8, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE);
			EncryptingReadableByteChannel dirIdReadChannel = Mockito.mock(EncryptingReadableByteChannel.class);

			Mockito.doReturn(dirIdReadChannel).when(resultSpy).wrapDecryptionAround(Mockito.any(), Mockito.eq(cryptor));
			Mockito.doAnswer(invocationOnMock -> {
				try (ReadableByteChannel channel = Files.newByteChannel(dirIdFile, StandardOpenOption.READ)) {
					return channel.read(invocationOnMock.getArgument(0));
				}
			}).when(dirIdReadChannel).read(Mockito.any());
			Mockito.when(fileNameCryptor.hashDirectoryId(Mockito.eq(dirId.substring(0, 36)))).thenReturn("123456");

			var maybeDirId = resultSpy.retrieveDirId(cipherOrphan, cryptor);

			Assertions.assertTrue(maybeDirId.isEmpty());
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
				baseEncodingClass.when(() -> BaseEncoding.base64Url()).thenReturn(base64url);
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
				baseEncodingClass.when(() -> BaseEncoding.base64Url()).thenReturn(base64url);
				Mockito.doReturn("adopted_shortened").when(base64url).encode(Mockito.any());

				result.adoptOrphanedResource(oldCipherPath, newClearName, true, stepParentDir, fileNameCryptor, sha1);
			}

			Assertions.assertTrue(Files.exists(stepParentDir.path.resolve("adopted_shortened.c9s")));
			Assertions.assertEquals("adopted.c9r", Files.readString(stepParentDir.path.resolve("adopted_shortened.c9s/name.c9s")));
			Assertions.assertTrue(Files.notExists(oldCipherPath));
		}

	}


	@Test
	@DisplayName("fix() prepares vault, process every resource in orphanDir and deletes orphanDir")
	public void testFix() throws IOException {
		result = new OrphanDir(dataDir.relativize(cipherOrphan));
		var resultSpy = Mockito.spy(result);

		Path orphan1 = cipherOrphan.resolve("orphan1.c9r");
		Path orphan2 = cipherOrphan.resolve("orphan2.c9s");
		Files.createFile(orphan1);
		Files.createDirectories(orphan2);

		CryptoPathMapper.CiphertextDirectory stepParentDir = new CryptoPathMapper.CiphertextDirectory("aaaaaa", dataDir.resolve("22/2222"));

		VaultConfig config = Mockito.mock(VaultConfig.class);
		Mockito.doReturn(170).when(config).getShorteningThreshold();
		Masterkey masterkey = Mockito.mock(Masterkey.class);
		Cryptor generalCryptor = Mockito.mock(Cryptor.class);
		Mockito.doReturn(fileNameCryptor).when(generalCryptor).fileNameCryptor();

		Mockito.doReturn(cipherRecovery).when(resultSpy).prepareRecoveryDir(pathToVault, fileNameCryptor);
		Mockito.doReturn(stepParentDir).when(resultSpy).prepareStepParent(Mockito.eq(dataDir), Mockito.eq(cipherRecovery), Mockito.eq(fileNameCryptor), Mockito.any());
		Mockito.doAnswer(invocationOnMock -> {
			Files.delete((Path) invocationOnMock.getArgument(0));
			return null;
		}).when(resultSpy).adoptOrphanedResource(Mockito.any(), Mockito.any(), Mockito.anyBoolean(), Mockito.eq(stepParentDir), Mockito.eq(fileNameCryptor), Mockito.any());

		resultSpy.fix(pathToVault, config, masterkey, generalCryptor);

		Mockito.verify(resultSpy, Mockito.times(2)).adoptOrphanedResource(Mockito.any(), Mockito.any(), Mockito.anyBoolean(), Mockito.eq(stepParentDir), Mockito.eq(fileNameCryptor), Mockito.any());
		Assertions.assertTrue(Files.notExists(cipherOrphan));
	}


	@Test
	@DisplayName("results with same orphan have write to same cleartext stepparent")
	public void testFixRepeated() throws IOException {
		VaultConfig config = Mockito.mock(VaultConfig.class);
		Mockito.doReturn(170).when(config).getShorteningThreshold();
		Masterkey masterkey = Mockito.mock(Masterkey.class);
		Cryptor generalCryptor = Mockito.mock(Cryptor.class);
		Mockito.doReturn(fileNameCryptor).when(generalCryptor).fileNameCryptor();

		AtomicReference<String> clearStepparentNameRef = new AtomicReference<>("");

		var interruptedResult = new OrphanDir(dataDir.relativize(cipherOrphan));
		var interruptedSpy = Mockito.spy(interruptedResult);
		Mockito.doReturn(cipherRecovery).when(interruptedSpy).prepareRecoveryDir(pathToVault, fileNameCryptor);
		Mockito.doAnswer(invocation -> {
			clearStepparentNameRef.set((String) invocation.getArgument(3));
			throw new IOException("Interrupt");
		}).when(interruptedSpy).prepareStepParent(Mockito.eq(dataDir), Mockito.eq(cipherRecovery), Mockito.eq(fileNameCryptor), Mockito.any());

		var continuedResult = new OrphanDir(dataDir.relativize(cipherOrphan));
		var continuedSpy = Mockito.spy(continuedResult);
		Mockito.doReturn(cipherRecovery).when(continuedSpy).prepareRecoveryDir(pathToVault, fileNameCryptor);
		Mockito.doThrow(IOException.class).when(continuedSpy).prepareStepParent(Mockito.any(), Mockito.any(), Mockito.any(), Mockito.any());

		Assertions.assertThrows(IOException.class, () -> interruptedSpy.fix(pathToVault, config, masterkey, generalCryptor));
		Assertions.assertThrows(IOException.class, () -> continuedSpy.fix(pathToVault, config, masterkey, generalCryptor));

		Mockito.verify(continuedSpy).prepareStepParent(dataDir, cipherRecovery, fileNameCryptor, clearStepparentNameRef.get());
	}


	@Test
	@DisplayName("orphaned recovery dir will only be reintegrated")
	public void testFixOrphanedRecoveryDir() throws IOException {
		Path orphanedRecovery = dataDir.resolve("11/1111");
		result = new OrphanDir(dataDir.relativize(orphanedRecovery));
		var resultSpy = Mockito.spy(result);

		Path orphan1 = orphanedRecovery.resolve("orphan1.c9r");
		Path orphan2 = orphanedRecovery.resolve("orphan2.c9r");
		Files.createDirectories(orphan1);
		Files.createDirectories(orphan2);


		VaultConfig config = Mockito.mock(VaultConfig.class);
		Mockito.doReturn(170).when(config).getShorteningThreshold();
		Masterkey masterkey = Mockito.mock(Masterkey.class);
		Cryptor generalCryptor = Mockito.mock(Cryptor.class);
		Mockito.doReturn(fileNameCryptor).when(generalCryptor).fileNameCryptor();
		Mockito.doReturn(cipherRecovery).when(resultSpy).prepareRecoveryDir(pathToVault, fileNameCryptor);

		resultSpy.fix(pathToVault, config, masterkey, generalCryptor);

		Mockito.verify(resultSpy, Mockito.never()).prepareStepParent(Mockito.eq(dataDir), Mockito.eq(cipherRecovery), Mockito.eq(fileNameCryptor), Mockito.any());
		Mockito.verify(resultSpy, Mockito.never()).adoptOrphanedResource(Mockito.any(), Mockito.any(), Mockito.anyBoolean(), Mockito.any(), Mockito.eq(fileNameCryptor), Mockito.any());
		Mockito.verify(resultSpy).prepareRecoveryDir(pathToVault, fileNameCryptor);
	}


	//TODO: write tests when dirId exists
}
