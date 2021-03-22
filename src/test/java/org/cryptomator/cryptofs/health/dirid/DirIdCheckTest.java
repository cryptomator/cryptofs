package org.cryptomator.cryptofs.health.dirid;

import org.cryptomator.cryptofs.health.api.DiagnosticResult;
import org.cryptomator.cryptolib.api.Cryptor;
import org.cryptomator.cryptolib.api.FileNameCryptor;
import org.hamcrest.CoreMatchers;
import org.hamcrest.MatcherAssert;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.Mockito;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.Set;

public class DirIdCheckTest {

	private Cryptor cryptor;
	private FileNameCryptor fileNameCryptor;

	@BeforeEach
	public void setup() {
		cryptor = Mockito.mock(Cryptor.class);
		fileNameCryptor = Mockito.mock(FileNameCryptor.class);
		Mockito.when(cryptor.fileNameCryptor()).thenReturn(fileNameCryptor);
	}

	@Test
	@DisplayName("DirVisitor collects relevant dir.c9r contents")
	public void testVisitorCollectsDirC9rFiles(@TempDir Path tmpDir) throws IOException {
		var dirStructure = "AA/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/foo=.c9r/dir.c9r = aa-foo-dir\n"
				+ "A/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/bar=.c9r/dir.c9r = aa-bar-dir\n"
				+ "AA/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/baz=.c9r/symlink.c9r = aa-baz-link\n"
				+ "BB/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbb/foo=.c9r/dir.c9r = bb-foo-dir\n"
				+ "BB/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbb/foo=.c9r/unrelated/dir.c9r = should-not-contain";
		dirStructure.lines().forEach(line -> initDirStructure(tmpDir, line));
		var results = new ArrayList<DiagnosticResult>();
		var visitor = new DirIdCheck.DirVisitor(tmpDir, results);

		Files.walkFileTree(tmpDir, Set.of(), 4, visitor);

		MatcherAssert.assertThat(visitor.dirIds, Matchers.hasKey("aa-foo-dir"));
		MatcherAssert.assertThat(visitor.dirIds, Matchers.hasKey("aa-bar-dir"));
		MatcherAssert.assertThat(visitor.dirIds, Matchers.hasKey("bb-foo-dir"));
		MatcherAssert.assertThat(visitor.dirIds, CoreMatchers.not(Matchers.hasKey("should-not-contain")));
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