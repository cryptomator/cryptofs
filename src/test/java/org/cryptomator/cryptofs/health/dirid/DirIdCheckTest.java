package org.cryptomator.cryptofs.health.dirid;

import com.google.common.jimfs.Configuration;
import com.google.common.jimfs.Jimfs;
import org.cryptomator.cryptofs.common.CustomMatchers;
import org.cryptomator.cryptofs.health.api.DiagnosticResult;
import org.cryptomator.cryptolib.api.Cryptor;
import org.cryptomator.cryptolib.api.FileNameCryptor;
import org.hamcrest.CoreMatchers;
import org.hamcrest.MatcherAssert;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileSystem;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.function.Predicate;

public class DirIdCheckTest {

	private static final String VAULT_STRUCTURE = """
			AA/aaaa/foo=.c9r/dir.c9r = BBbbbb
			AA/aaaa/bar=.c9r/dir.c9r = CCcccc
			AA/aaaa/baz=.c9r/symlink.c9r = linktarget
			BB/bbbb/foo=.c9r/dir.c9r = CCcccc
			BB/bbbb/bar=.c9r/dir.c9r = ffffffffffff-aaaaaaaaaaaa-tttttttttttt
			BB/bbbb/foo=.c9r/unrelated/dir.c9r = unrelatedfile
			CC/cccc/foo=.c9r = file
			""";

	private FileSystem fs;
	private Cryptor cryptor;
	private FileNameCryptor fileNameCryptor;
	private Path dataRoot;

	@BeforeEach
	public void setup() {
		fs = Jimfs.newFileSystem(Configuration.unix());
		cryptor = Mockito.mock(Cryptor.class);
		fileNameCryptor = Mockito.mock(FileNameCryptor.class);
		dataRoot = fs.getPath("/d");
		VAULT_STRUCTURE.lines().forEach(line -> initDirStructure(dataRoot, line));

		Mockito.when(cryptor.fileNameCryptor()).thenReturn(fileNameCryptor);
		Mockito.when(fileNameCryptor.hashDirectoryId(Mockito.any())).then(i -> i.getArgument(0));
	}

	@AfterEach
	public void teardown() throws IOException {
		fs.close();
	}

	@Nested
	@DisplayName("DirVisitor")
	class Visitor {

		private List<DiagnosticResult> results;
		private DirIdCheck.DirVisitor visitor;

		@BeforeEach
		public void setup() {
			results = new ArrayList<>();
			visitor = new DirIdCheck.DirVisitor(dataRoot, results);
		}

		@Test
		@DisplayName("collects relevant dir.c9r contents")
		public void testVisitorCollectsDirC9rFiles() throws IOException {
			Files.walkFileTree(dataRoot, Set.of(), 4, visitor);

			MatcherAssert.assertThat(visitor.dirIds, Matchers.hasKey("")); // root dir id always present
			MatcherAssert.assertThat(visitor.dirIds, Matchers.hasKey("BBbbbb"));
			MatcherAssert.assertThat(visitor.dirIds, Matchers.hasKey("CCcccc"));
			MatcherAssert.assertThat(visitor.dirIds, CoreMatchers.not(Matchers.hasKey("linktarget")));
			MatcherAssert.assertThat(visitor.dirIds, CoreMatchers.not(Matchers.hasKey("unrelatedfile")));
			MatcherAssert.assertThat(visitor.dirIds, CoreMatchers.not(Matchers.hasKey("file")));
		}

		@Test
		@DisplayName("collects 2nd-level dirs")
		public void testVisitorCollects2ndLvlDirs() throws IOException {
			Files.walkFileTree(dataRoot, Set.of(), 4, visitor);

			MatcherAssert.assertThat(visitor.secondLevelDirs, Matchers.hasItem(fs.getPath("AA/aaaa")));
			MatcherAssert.assertThat(visitor.secondLevelDirs, Matchers.hasItem(fs.getPath("BB/bbbb")));
			MatcherAssert.assertThat(visitor.secondLevelDirs, Matchers.hasItem(fs.getPath("CC/cccc")));
		}

		@Test
		@DisplayName("detects reused dirID: CCcccc")
		public void testVisitorDetectsReusedDirId() throws IOException {
			Files.walkFileTree(dataRoot, Set.of(), 4, visitor);

			Predicate<DirIdCollision> expectedCollision = dirIdCollision -> "CCcccc".equals(dirIdCollision.dirId);
			MatcherAssert.assertThat(results, Matchers.hasItem(CustomMatchers.matching(DirIdCollision.class, expectedCollision, "Directory ID reused: CCcccc")));
		}

		@Test
		@DisplayName("detects obese dirID in /d/BB/bbbb/bar=.c9r/dir.c9r")
		public void testVisitorDetectsObeseDirId() throws IOException {
			Files.walkFileTree(dataRoot, Set.of(), 4, visitor);

			Predicate<ObeseDirFile> expectedObeseFile = obeseDirFile -> "/d/BB/bbbb/bar=.c9r/dir.c9r".equals(obeseDirFile.dirFile.toString());
			MatcherAssert.assertThat(results, Matchers.hasItem(CustomMatchers.matching(ObeseDirFile.class, expectedObeseFile, "Obese dir file: /d/BB/bbbb/bar=.c9r/dir.c9r")));
		}

	}

	private static void initDirStructure(Path root, String line) throws UncheckedIOException {
		try {
			if (line.contains(" = ")) {
				var sep = line.indexOf(" = ");
				var file = line.substring(0, sep);
				var contents = line.substring(sep + 3);
				Files.createDirectories(root.resolve(file).getParent());
				Files.writeString(root.resolve(file), contents, StandardCharsets.US_ASCII, StandardOpenOption.CREATE_NEW);
			} else {
				Files.createDirectories(root.resolve(line));
			}
		} catch (IOException e) {
			throw new UncheckedIOException(e);
		}
	}

}