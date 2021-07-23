package org.cryptomator.cryptofs.health.type;

import com.google.common.jimfs.Configuration;
import com.google.common.jimfs.Jimfs;
import org.cryptomator.cryptofs.common.CustomMatchers;
import org.cryptomator.cryptofs.health.VaultStructureUtil;
import org.cryptomator.cryptofs.health.api.DiagnosticResult;
import org.cryptomator.cryptolib.api.Cryptor;
import org.hamcrest.MatcherAssert;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;

import java.io.IOException;
import java.nio.file.FileSystem;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Set;
import java.util.function.Consumer;
import java.util.function.Predicate;

public class CiphertextFileTypeCheckTest {

	private static final String VAULT_STRUCTURE = """
			AA/aaaa/foo=.c9r/dir.c9r = [EMPTY]
			AA/aaaa/bar=.c9s/contents.c9r = [EMPTY]
			AA/aaaa/baz=.c9s/symlink.c9r = [EMPTY] 
			BB/bbbb/foo=.c9r/
			BB/bbbb/bar=.c9s/
			BB/bbbb/baz=.c9r/name.c9s = [EMPTY]
			CC/cccc/foo=.c9r/dir.c9r = [EMPTY]
			CC/cccc/foo=.c9r/symlink.c9r = [EMPTY]
			CC/cccc/bar=.c9r/contents.c9r = [EMPTY]
			""";

	private FileSystem fs;
	private Cryptor cryptor;
	private Path dataRoot;

	@BeforeEach
	public void setup() {
		fs = Jimfs.newFileSystem(Configuration.unix());
		cryptor = Mockito.mock(Cryptor.class);
		dataRoot = fs.getPath("/d");
		VaultStructureUtil.initDirStructure(dataRoot, VAULT_STRUCTURE);
	}

	@AfterEach
	public void teardown() throws IOException {
		fs.close();
	}

	@Nested
	@DisplayName("TypeCheck DirVisitor")
	public class Visitor {

		private Consumer<DiagnosticResult> resultsCollector;
		private CiphertextFileTypeCheck.DirVisitor visitor;

		@BeforeEach
		public void setup() {
			resultsCollector = Mockito.mock(Consumer.class);
			visitor = new CiphertextFileTypeCheck.DirVisitor(resultsCollector);
		}

		@Test
		@DisplayName("tests if dirs ending with c9r are visited")
		public void testC9rDirsAreVisited() throws IOException {
			var visitorSpy = Mockito.spy(visitor);
			Files.walkFileTree(dataRoot, Set.of(), 4, visitorSpy);

			Path expectedVisit1 = dataRoot.resolve("AA/aaaa/foo=.c9r");
			Path expectedVisit2 = dataRoot.resolve("BB/bbbb/baz=.c9r");
			Path expectedVisit3 = dataRoot.resolve("CC/cccc/bar=.c9r");
			Mockito.verify(visitorSpy).preVisitDirectory(Mockito.eq(expectedVisit1), Mockito.any());
			Mockito.verify(visitorSpy).preVisitDirectory(Mockito.eq(expectedVisit2), Mockito.any());
			Mockito.verify(visitorSpy).preVisitDirectory(Mockito.eq(expectedVisit3), Mockito.any());
		}

		@Test
		@DisplayName("tests if dirs ending with c9s are visited")
		public void testC9sDirsAreVisited() throws IOException {
			var visitorSpy = Mockito.spy(visitor);
			Files.walkFileTree(dataRoot, Set.of(), 4, visitorSpy);

			Path expectedVisit1 = dataRoot.resolve("AA/aaaa/baz=.c9s");
			Path expectedVisit2 = dataRoot.resolve("BB/bbbb/bar=.c9s");
			Mockito.verify(visitorSpy).preVisitDirectory(Mockito.eq(expectedVisit1), Mockito.any());
			Mockito.verify(visitorSpy).preVisitDirectory(Mockito.eq(expectedVisit2), Mockito.any());
		}

		@Test
		@DisplayName("dir with only dir.c9r file should be a known")
		public void testSignatureDirFileProducesKnownType() throws IOException {
			Files.walkFileTree(dataRoot, Set.of(), 4, visitor);

			Predicate<KnownType> expectedKnownType = expectedType -> expectedType.cipherDir.endsWith("AA/aaaa/foo=.c9r");

			ArgumentCaptor<DiagnosticResult> resultCaptor = ArgumentCaptor.forClass(DiagnosticResult.class);
			Mockito.verify(resultsCollector, Mockito.atLeastOnce()).accept(resultCaptor.capture());
			MatcherAssert.assertThat(resultCaptor.getAllValues(), Matchers.hasItem(CustomMatchers.matching(KnownType.class, expectedKnownType, "aaaa/foo.c9r as known type")));
		}

		@Test
		@DisplayName("dir with only symlink.c9r should be a known")
		public void testSignatureSymlinkFileProducesKnownType() throws IOException {
			Files.walkFileTree(dataRoot, Set.of(), 4, visitor);

			Predicate<KnownType> expectedKnownType = expectedType -> expectedType.cipherDir.endsWith("AA/aaaa/baz=.c9s");

			ArgumentCaptor<DiagnosticResult> resultCaptor = ArgumentCaptor.forClass(DiagnosticResult.class);
			Mockito.verify(resultsCollector, Mockito.atLeastOnce()).accept(resultCaptor.capture());
			MatcherAssert.assertThat(resultCaptor.getAllValues(), Matchers.hasItem(CustomMatchers.matching(KnownType.class, expectedKnownType, "aaaa/baz.c9s as known type")));
		}

		@Test
		@DisplayName("c9s dir with only contents.c9r should be a known")
		public void testSignatureContentsFileWithC9sProducesKnownType() throws IOException {
			Files.walkFileTree(dataRoot, Set.of(), 4, visitor);

			Predicate<KnownType> expectedKnownType = expectedType -> expectedType.cipherDir.endsWith("AA/aaaa/bar=.c9s");

			ArgumentCaptor<DiagnosticResult> resultCaptor = ArgumentCaptor.forClass(DiagnosticResult.class);
			Mockito.verify(resultsCollector, Mockito.atLeastOnce()).accept(resultCaptor.capture());
			MatcherAssert.assertThat(resultCaptor.getAllValues(), Matchers.hasItem(CustomMatchers.matching(KnownType.class, expectedKnownType, "aaaa/bar.c9s as known type")));
		}

		@Test
		@DisplayName("a dir without any signature file should be unknown")
		public void testDirWithoutSignatureFileProducesUnknownType() throws IOException {
			Files.walkFileTree(dataRoot, Set.of(), 4, visitor);

			Predicate<UnknownType> expectedUnknownType1 = expectedType -> expectedType.cipherDir.endsWith("BB/bbbb/foo=.c9r");
			Predicate<UnknownType> expectedUnknownType2 = expectedType -> expectedType.cipherDir.endsWith("BB/bbbb/bar=.c9s");

			ArgumentCaptor<DiagnosticResult> resultCaptor = ArgumentCaptor.forClass(DiagnosticResult.class);
			Mockito.verify(resultsCollector, Mockito.atLeast(2)).accept(resultCaptor.capture());
			MatcherAssert.assertThat(resultCaptor.getAllValues(), Matchers.hasItem(CustomMatchers.matching(UnknownType.class, expectedUnknownType1, "bbbb/foo=.c9r as unknown type")));
			MatcherAssert.assertThat(resultCaptor.getAllValues(), Matchers.hasItem(CustomMatchers.matching(UnknownType.class, expectedUnknownType2, "bbbb/bar=.c9s as unknown type")));
		}

		@Test
		@DisplayName("a dir without at least two signature files should be ambiguous")
		public void testDirWithAtLeastTwoSignatureFilesProducesAmbiguousType() throws IOException {
			Files.walkFileTree(dataRoot, Set.of(), 4, visitor);

			Predicate<AmbiguousType> ambiguousType = expectedType -> expectedType.cipherDir.endsWith("CC/cccc/foo=.c9r");

			ArgumentCaptor<DiagnosticResult> resultCaptor = ArgumentCaptor.forClass(DiagnosticResult.class);
			Mockito.verify(resultsCollector, Mockito.atLeastOnce()).accept(resultCaptor.capture());
			MatcherAssert.assertThat(resultCaptor.getAllValues(), Matchers.hasItem(CustomMatchers.matching(AmbiguousType.class, ambiguousType, "cccc/foo=.c9r as unknown type")));
		}

		@Test
		@DisplayName("a c9r dir with only contents.c9r file should be ambiguous")
		public void testC9rDirWithContentsFileProducesAmbiguousType() throws IOException {
			Files.walkFileTree(dataRoot, Set.of(), 4, visitor);

			Predicate<AmbiguousType> ambiguousType = expectedType -> expectedType.cipherDir.endsWith("CC/cccc/bar=.c9r");

			ArgumentCaptor<DiagnosticResult> resultCaptor = ArgumentCaptor.forClass(DiagnosticResult.class);
			Mockito.verify(resultsCollector, Mockito.atLeastOnce()).accept(resultCaptor.capture());
			MatcherAssert.assertThat(resultCaptor.getAllValues(), Matchers.hasItem(CustomMatchers.matching(AmbiguousType.class, ambiguousType, "cccc/bar.c9r as unknown type")));
		}

	}
}
