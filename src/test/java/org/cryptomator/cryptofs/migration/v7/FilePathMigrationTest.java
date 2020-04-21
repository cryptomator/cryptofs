package org.cryptomator.cryptofs.migration.v7;

import com.google.common.io.MoreFiles;
import com.google.common.io.RecursiveDeleteOption;
import com.google.common.jimfs.Configuration;
import com.google.common.jimfs.Jimfs;
import org.hamcrest.CoreMatchers;
import org.hamcrest.MatcherAssert;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.converter.ArgumentConversionException;
import org.junit.jupiter.params.converter.ConvertWith;
import org.junit.jupiter.params.converter.SimpleArgumentConverter;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mockito;

import java.io.IOException;
import java.nio.file.FileSystem;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Base64;
import java.util.Optional;

import static java.nio.charset.StandardCharsets.UTF_8;

public class FilePathMigrationTest {

	private Path oldPath = Mockito.mock(Path.class, "oldPath");

	@ParameterizedTest(name = "getOldCanonicalNameWithoutTypePrefix() expected to be {1} for {0}")
	@CsvSource({
			"ORSXG5A=,ORSXG5A=",
			"0ORSXG5A=,ORSXG5A=",
			"1SORSXG5A=,ORSXG5A=",
	})
	public void testGetOldCanonicalNameWithoutTypePrefix(String oldCanonicalName, String expectedResult) {
		FilePathMigration migration = new FilePathMigration(oldPath, oldCanonicalName);

		Assertions.assertEquals(expectedResult, migration.getOldCanonicalNameWithoutTypePrefix());
	}
	
	@ParameterizedTest(name = "getDecodedCiphertext() expected to be {1} for {0}")
	@CsvSource({
			"ORSXG5A=,dGVzdA==",
			"0ORSXG5A=,dGVzdA==",
			"1SORSXG5A=,dGVzdA==",
	})
	public void testGetDecodedCiphertext(String oldCanonicalName, @ConvertWith(ByteArrayArgumentConverter.class) byte[] expected) throws InvalidOldFilenameException {
		FilePathMigration migration = new FilePathMigration(oldPath, oldCanonicalName);
		Assertions.assertArrayEquals(expected, migration.getDecodedCiphertext());
	}

	@ParameterizedTest(name = "getDecodedCiphertext() throws InvalidOldFilenameException for {0}")
	@ValueSource(strings = {
		"ORSXG5=A",
		"ORSX=G5A"
	})
	public void testMalformedGetDecodedCiphertext(String oldCanonicalName) {
		FilePathMigration migration = new FilePathMigration(oldPath, oldCanonicalName);

		InvalidOldFilenameException e = Assertions.assertThrows(InvalidOldFilenameException.class, () -> {
			migration.getDecodedCiphertext();
		});
		Assertions.assertTrue(e.getMessage().contains(oldPath.toString()));
	}

	@ParameterizedTest(name = "getNewInflatedName() expected to be {1} for {0}")
	@CsvSource({
			"ORSXG5A=,dGVzdA==.c9r",
			"0ORSXG5A=,dGVzdA==.c9r",
			"1SORSXG5A=,dGVzdA==.c9r",
	})
	public void testGetNewInflatedName(String oldCanonicalName, String expectedResult) throws InvalidOldFilenameException {
		FilePathMigration migration = new FilePathMigration(oldPath, oldCanonicalName);

		Assertions.assertEquals(expectedResult, migration.getNewInflatedName());
	}

	@ParameterizedTest(name = "getNewInflatedName() expected to be {1} for {0}")
	@CsvSource({
			"ORSXG5A=,dGVzdA==.c9r",
			"ORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSQ====,dGVzdCB0ZXN0IHRlc3QgdGVzdCB0ZXN0IHRlc3QgdGVzdCB0ZXN0IHRlc3QgdGVzdCB0ZXN0IHRlc3QgdGVzdCB0ZXN0IHRlc3QgdGVzdCB0ZXN0IHRlc3QgdGVzdCB0ZXN0IHRlc3QgdGVzdCB0ZXN0IHRlc3QgdGVzdCB0ZXN0IHRlc3QgdGVzdCB0ZXN0IHRlc3QgdGVzdCB0ZXN0IHRl.c9r",
			"ORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG===,30xtS3YjsiMJRwu1oAVc_0S2aAU=.c9s",
	})
	public void testGetNewDeflatedName(String oldCanonicalName, String expectedResult) throws InvalidOldFilenameException {
		FilePathMigration migration = new FilePathMigration(oldPath, oldCanonicalName);

		Assertions.assertEquals(expectedResult, migration.getNewDeflatedName());
	}

	@ParameterizedTest(name = "isDirectory() expected to be {1} for {0}")
	@CsvSource({
			"ORSXG5A=,false",
			"0ORSXG5A=,true",
			"1SORSXG5A=,false",
	})
	public void testIsDirectory(String oldCanonicalName, boolean expectedResult) {
		FilePathMigration migration = new FilePathMigration(oldPath, oldCanonicalName);

		Assertions.assertEquals(expectedResult, migration.isDirectory());
	}

	@ParameterizedTest(name = "isSymlink() expected to be {1} for {0}")
	@CsvSource({
			"ORSXG5A=,false",
			"0ORSXG5A=,false",
			"1SORSXG5A=,true",
	})
	public void testIsSymlink(String oldCanonicalName, boolean expectedResult) {
		FilePathMigration migration = new FilePathMigration(oldPath, oldCanonicalName);

		Assertions.assertEquals(expectedResult, migration.isSymlink());
	}

	@ParameterizedTest(name = "getTargetPath() expected to be {1} for {0}")
	@CsvSource({
			"ORSXG5A=,'',dGVzdA==.c9r",
			"0ORSXG5A=,'',dGVzdA==.c9r/dir.c9r",
			"1SORSXG5A=,'',dGVzdA==.c9r/symlink.c9r",
			"ORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG===,'',30xtS3YjsiMJRwu1oAVc_0S2aAU=.c9s/contents.c9r",
			"0ORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG===,'',30xtS3YjsiMJRwu1oAVc_0S2aAU=.c9s/dir.c9r",
			"1SORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG===,'',30xtS3YjsiMJRwu1oAVc_0S2aAU=.c9s/symlink.c9r",
			"ORSXG5A=,'_1',dGVzdA==_1.c9r",
			"ORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG===,'_123',30xtS3YjsiMJRwu1oAVc_0S2aAU=_123.c9s/contents.c9r",
	})
	public void testGetTargetPath(String oldCanonicalName, String attemptSuffix, String expected) throws InvalidOldFilenameException {
		Path old = Paths.get("/tmp/foo");
		FilePathMigration migration = new FilePathMigration(old, oldCanonicalName);

		Path result = migration.getTargetPath(attemptSuffix);

		Assertions.assertEquals(old.resolveSibling(expected), result);
	}

	@DisplayName("FilePathMigration.parse(...)")
	@Nested
	@TestInstance(TestInstance.Lifecycle.PER_CLASS)
	class Parsing {

		private FileSystem fs;
		private Path vaultRoot;
		private Path dataDir;
		private Path metaDir;

		@BeforeAll
		public void beforeAll() {
			fs = Jimfs.newFileSystem(Configuration.unix());
			vaultRoot = fs.getPath("/vaultDir");
			dataDir = vaultRoot.resolve("d");
			metaDir = vaultRoot.resolve("m");
		}

		@BeforeEach
		public void beforeEach() throws IOException {
			Files.createDirectory(vaultRoot);
			Files.createDirectory(dataDir);
			Files.createDirectory(metaDir);
		}

		@AfterEach
		public void afterEach() throws IOException {
			MoreFiles.deleteRecursively(vaultRoot, RecursiveDeleteOption.ALLOW_INSECURE);
		}

		@DisplayName("inflate with non-existing metadata file")
		@Test
		public void testInflateWithMissingMetadata() {
			UninflatableFileException e = Assertions.assertThrows(UninflatableFileException.class, () -> {
				FilePathMigration.inflate(vaultRoot, "NTJDZUB3J5S25LGO7CD4TE5VOJCSW7HF.lng");

			});
			MatcherAssert.assertThat(e.getCause(), CoreMatchers.instanceOf(NoSuchFileException.class));
		}

		@DisplayName("inflate with too large metadata file")
		@Test
		public void testInflateWithTooLargeMetadata() throws IOException {
			Path lngFilePath = metaDir.resolve("NT/JD/NTJDZUB3J5S25LGO7CD4TE5VOJCSW7HF.lng");
			Files.createDirectories(lngFilePath.getParent());
			Files.write(lngFilePath, new byte[10 * 1024 + 1]);

			UninflatableFileException e = Assertions.assertThrows(UninflatableFileException.class, () -> {
				FilePathMigration.inflate(vaultRoot, "NTJDZUB3J5S25LGO7CD4TE5VOJCSW7HF.lng");

			});
			MatcherAssert.assertThat(e.getMessage(), CoreMatchers.containsString("Unexpectedly large file"));
		}

		@DisplayName("inflate")
		@ParameterizedTest(name = "inflate(vaultRoot, {0})")
		@CsvSource({
				"NTJDZUB3J5S25LGO7CD4TE5VOJCSW7HF.lng,NT/JD/NTJDZUB3J5S25LGO7CD4TE5VOJCSW7HF.lng,ORSXG5A=",
				"ZNPCXPWRWYFOGTZHVDBOOQDYPAMKKI5R.lng,ZN/PC/ZNPCXPWRWYFOGTZHVDBOOQDYPAMKKI5R.lng,0ORSXG5A=",
				"NUC3VFSMWKLD4526JDZKSE5V2IIMSYW5.lng,NU/C3/NUC3VFSMWKLD4526JDZKSE5V2IIMSYW5.lng,1SORSXG5A=",
		})
		public void testInflate(String canonicalLongFileName, String metadataFilePath, String expected) throws IOException {
			Path lngFilePath = metaDir.resolve(metadataFilePath);
			Files.createDirectories(lngFilePath.getParent());
			Files.write(lngFilePath, expected.getBytes(UTF_8));

			String result = FilePathMigration.inflate(vaultRoot, canonicalLongFileName);

			Assertions.assertEquals(expected, result);
		}

		@DisplayName("unrelated files")
		@ParameterizedTest(name = "parse(vaultRoot, {0}) expected to be unparsable")
		@ValueSource(strings = {
				"00/000000000000000000000000000000/.DS_Store",
				"00/000000000000000000000000000000/foo",
				"00/000000000000000000000000000000/ORSXG5A=.c9r", // already migrated
				"00/000000000000000000000000000000/ORSXG5A=.c9s", // already migrated
				"00/000000000000000000000000000000/ORSXG5A", // removed one char
				"00/000000000000000000000000000000/NTJDZUB3J5S25LGO7CD4TE5VOJCSW7H.lng", // removed one char
		})
		public void testParseUnrelatedFile(String oldPath) throws IOException {
			Path path = dataDir.resolve(oldPath);

			Optional<FilePathMigration> migration = FilePathMigration.parse(vaultRoot, path);

			Assertions.assertFalse(migration.isPresent());
		}

		@DisplayName("regular files")
		@ParameterizedTest(name = "parse(vaultRoot, {0}).getOldCanonicalName() expected to be {1}")
		@CsvSource({
				"00/000000000000000000000000000000/ORSXG5A=,ORSXG5A=",
				"00/000000000000000000000000000000/0ORSXG5A=,0ORSXG5A=",
				"00/000000000000000000000000000000/1SORSXG5A=,1SORSXG5A=",
				"00/000000000000000000000000000000/conflict_1SORSXG5A=,1SORSXG5A=",
				"00/000000000000000000000000000000/1SORSXG5A= (conflict),1SORSXG5A=",
		})
		public void testParseNonShortenedFile(String oldPath, String expected) throws IOException {
			Path path = dataDir.resolve(oldPath);

			Optional<FilePathMigration> migration = FilePathMigration.parse(vaultRoot, path);

			Assertions.assertTrue(migration.isPresent());
			Assertions.assertEquals(expected, migration.get().getOldCanonicalName());
		}

		@DisplayName("shortened files")
		@ParameterizedTest(name = "parse(vaultRoot, {0}).getOldCanonicalName() expected to be {2}")
		@CsvSource({
				"00/000000000000000000000000000000/NTJDZUB3J5S25LGO7CD4TE5VOJCSW7HF.lng,NT/JD/NTJDZUB3J5S25LGO7CD4TE5VOJCSW7HF.lng,ORSXG5A=",
				"00/000000000000000000000000000000/ZNPCXPWRWYFOGTZHVDBOOQDYPAMKKI5R.lng,ZN/PC/ZNPCXPWRWYFOGTZHVDBOOQDYPAMKKI5R.lng,0ORSXG5A=",
				"00/000000000000000000000000000000/NUC3VFSMWKLD4526JDZKSE5V2IIMSYW5.lng,NU/C3/NUC3VFSMWKLD4526JDZKSE5V2IIMSYW5.lng,1SORSXG5A=",
				"00/000000000000000000000000000000/conflict_NUC3VFSMWKLD4526JDZKSE5V2IIMSYW5.lng,NU/C3/NUC3VFSMWKLD4526JDZKSE5V2IIMSYW5.lng,1SORSXG5A=",
				"00/000000000000000000000000000000/NUC3VFSMWKLD4526JDZKSE5V2IIMSYW5 (conflict).lng,NU/C3/NUC3VFSMWKLD4526JDZKSE5V2IIMSYW5.lng,1SORSXG5A=",
		})
		public void testParseShortenedFile(String oldPath, String metadataFilePath, String expected) throws IOException {
			Path path = dataDir.resolve(oldPath);
			Path lngFilePath = metaDir.resolve(metadataFilePath);
			Files.createDirectories(lngFilePath.getParent());
			Files.write(lngFilePath, expected.getBytes(UTF_8));

			Optional<FilePathMigration> migration = FilePathMigration.parse(vaultRoot, path);

			Assertions.assertTrue(migration.isPresent());
			Assertions.assertEquals(expected, migration.get().getOldCanonicalName());
		}

	}

	@DisplayName("FilePathMigration.parse(...).get().migrate(...)")
	@Nested
	@TestInstance(TestInstance.Lifecycle.PER_CLASS)
	class Migrating {

		private FileSystem fs;
		private Path vaultRoot;
		private Path dataDir;
		private Path metaDir;

		@BeforeAll
		public void beforeAll() {
			fs = Jimfs.newFileSystem(Configuration.unix());
			vaultRoot = fs.getPath("/vaultDir");
			dataDir = vaultRoot.resolve("d");
			metaDir = vaultRoot.resolve("m");
		}

		@BeforeEach
		public void beforeEach() throws IOException {
			Files.createDirectory(vaultRoot);
			Files.createDirectory(dataDir);
			Files.createDirectory(metaDir);
		}

		@AfterEach
		public void afterEach() throws IOException {
			MoreFiles.deleteRecursively(vaultRoot, RecursiveDeleteOption.ALLOW_INSECURE);
		}

		@DisplayName("migrate non-shortened files")
		@ParameterizedTest(name = "migrating {0} to {1}")
		@CsvSource({
				"00/000000000000000000000000000000/ORSXG5A=,00/000000000000000000000000000000/dGVzdA==.c9r",
				"00/000000000000000000000000000000/0ORSXG5A=,00/000000000000000000000000000000/dGVzdA==.c9r/dir.c9r",
				"00/000000000000000000000000000000/1SORSXG5A=,00/000000000000000000000000000000/dGVzdA==.c9r/symlink.c9r",
				"00/000000000000000000000000000000/conflict_ORSXG5A=,00/000000000000000000000000000000/dGVzdA==.c9r",
				"00/000000000000000000000000000000/0ORSXG5A= (conflict),00/000000000000000000000000000000/dGVzdA==.c9r/dir.c9r",
				"00/000000000000000000000000000000/conflict_1SORSXG5A= (conflict),00/000000000000000000000000000000/dGVzdA==.c9r/symlink.c9r",
		})
		public void testMigrateUnshortened(String oldPathStr, String expectedResult) throws IOException {
			Path oldPath = dataDir.resolve(oldPathStr);
			Files.createDirectories(oldPath.getParent());
			Files.write(oldPath, "test".getBytes(UTF_8));

			Path newPath = FilePathMigration.parse(vaultRoot, oldPath).get().migrate();

			Assertions.assertEquals(dataDir.resolve(expectedResult), newPath);
			Assertions.assertTrue(Files.exists(newPath));
			Assertions.assertFalse(Files.exists(oldPath));
		}

		@DisplayName("migrate shortened files")
		@ParameterizedTest(name = "migrating {0} to {3}")
		@CsvSource({
				"00/000000000000000000000000000000/NTJDZUB3J5S25LGO7CD4TE5VOJCSW7HF.lng,NT/JD/NTJDZUB3J5S25LGO7CD4TE5VOJCSW7HF.lng,ORSXG5A=,00/000000000000000000000000000000/dGVzdA==.c9r",
				"00/000000000000000000000000000000/ZNPCXPWRWYFOGTZHVDBOOQDYPAMKKI5R.lng,ZN/PC/ZNPCXPWRWYFOGTZHVDBOOQDYPAMKKI5R.lng,0ORSXG5A=,00/000000000000000000000000000000/dGVzdA==.c9r/dir.c9r",
				"00/000000000000000000000000000000/NUC3VFSMWKLD4526JDZKSE5V2IIMSYW5.lng,NU/C3/NUC3VFSMWKLD4526JDZKSE5V2IIMSYW5.lng,1SORSXG5A=,00/000000000000000000000000000000/dGVzdA==.c9r/symlink.c9r",
				"00/000000000000000000000000000000/LPFZEP7JSREQMANHG7PRTOLSEKJM5JP5.lng,LP/FZ/LPFZEP7JSREQMANHG7PRTOLSEKJM5JP5.lng,ORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG===,00/000000000000000000000000000000/30xtS3YjsiMJRwu1oAVc_0S2aAU=.c9s/contents.c9r",
				"00/000000000000000000000000000000/7LX7VYDWDWXRPL7ZKTTCVGUPMGPRNUSG.lng,7L/X7/7LX7VYDWDWXRPL7ZKTTCVGUPMGPRNUSG.lng,0ORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG===,00/000000000000000000000000000000/30xtS3YjsiMJRwu1oAVc_0S2aAU=.c9s/dir.c9r",
				"00/000000000000000000000000000000/MGBBDEW456AMIDODOA3FUOQ3WNYNQNHZ.lng,MG/BB/MGBBDEW456AMIDODOA3FUOQ3WNYNQNHZ.lng,1SORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG===,00/000000000000000000000000000000/30xtS3YjsiMJRwu1oAVc_0S2aAU=.c9s/symlink.c9r",
				"00/000000000000000000000000000000/conflict_NTJDZUB3J5S25LGO7CD4TE5VOJCSW7HF.lng,NT/JD/NTJDZUB3J5S25LGO7CD4TE5VOJCSW7HF.lng,ORSXG5A=,00/000000000000000000000000000000/dGVzdA==.c9r",
				"00/000000000000000000000000000000/MGBBDEW456AMIDODOA3FUOQ3WNYNQNHZ (conflict).lng,MG/BB/MGBBDEW456AMIDODOA3FUOQ3WNYNQNHZ.lng,1SORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG===,00/000000000000000000000000000000/30xtS3YjsiMJRwu1oAVc_0S2aAU=.c9s/symlink.c9r",
		})
		public void testMigrateShortened(String oldPathStr, String metadataFilePath, String canonicalOldName, String expectedResult) throws IOException {
			Path oldPath = dataDir.resolve(oldPathStr);
			Files.createDirectories(oldPath.getParent());
			Files.write(oldPath, "test".getBytes(UTF_8));
			Path lngFilePath = metaDir.resolve(metadataFilePath);
			Files.createDirectories(lngFilePath.getParent());
			Files.write(lngFilePath, canonicalOldName.getBytes(UTF_8));

			Path newPath = FilePathMigration.parse(vaultRoot, oldPath).get().migrate();

			Assertions.assertEquals(dataDir.resolve(expectedResult), newPath);
			Assertions.assertTrue(Files.exists(newPath));
			Assertions.assertFalse(Files.exists(oldPath));
		}


	}

	public static class ByteArrayArgumentConverter extends SimpleArgumentConverter {

		@Override
		protected Object convert(Object source, Class<?> targetType) throws ArgumentConversionException {
			Assertions.assertEquals(byte[].class, targetType, "Can only convert to byte[]");
			return Base64.getUrlDecoder().decode(String.valueOf(source));
		}
	}
}
