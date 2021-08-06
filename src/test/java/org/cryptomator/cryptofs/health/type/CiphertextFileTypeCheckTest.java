package org.cryptomator.cryptofs.health.type;

import com.google.common.jimfs.Configuration;
import com.google.common.jimfs.Jimfs;
import org.cryptomator.cryptofs.health.api.DiagnosticResult;
import org.hamcrest.MatcherAssert;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;

import java.io.IOException;
import java.nio.file.FileSystem;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Set;
import java.util.function.Consumer;

public class CiphertextFileTypeCheckTest {

	private FileSystem fs;
	private Path dataRoot;

	@BeforeEach
	public void setup() {
		fs = Jimfs.newFileSystem(Configuration.unix());
		dataRoot = fs.getPath("/d");
	}

	@AfterEach
	public void tearDown() throws IOException {
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
		@DisplayName("tests if dirs ending with c9r are visited and closer looked at")
		public void testC9rDirsAreVisited() throws IOException {
			Path p = dataRoot.resolve("AA/aaaa/foo=.c9r");
			Files.createDirectories(p);

			var visitorSpy = Mockito.spy(visitor);
			Files.walkFileTree(dataRoot, Set.of(), 3, visitorSpy);

			Mockito.verify(visitorSpy).visitFile(Mockito.eq(p), Mockito.any());
			Mockito.verify(visitorSpy).checkCiphertextType(p, false);
		}

		@Test
		@DisplayName("tests if dirs ending with c9s are visited and closer looked at")
		public void testC9sDirsAreVisited() throws IOException {
			Path p = dataRoot.resolve("AA/zzzz/bar=.c9s");
			Files.createDirectories(p);

			var visitorSpy = Mockito.spy(visitor);
			Files.walkFileTree(dataRoot, Set.of(), 3, visitorSpy);

			Mockito.verify(visitorSpy).visitFile(Mockito.eq(p), Mockito.any());
			Mockito.verify(visitorSpy).checkCiphertextType(p, true);
		}

		@Nested
		@DisplayName("Ciphertext type checks for c9r dir")
		public class C9rDirChecked {

			private Path c9rDir;

			@BeforeEach
			public void initialize() throws IOException {
				c9rDir = dataRoot.resolve("AA/pretended/c9rDir");
				Files.createDirectories(c9rDir);
			}

			@ParameterizedTest
			@DisplayName("c9r dir with only dir.c9r or symlink.c9r is known")
			@ValueSource(strings = {"dir.c9r", "symlink.c9r"})
			public void testSigDirOrSymlinkFileProduceKnownType(String typeFile) throws IOException {
				Files.createFile(c9rDir.resolve(typeFile));

				visitor.checkCiphertextType(c9rDir, false);

				ArgumentCaptor<DiagnosticResult> resultCaptor = ArgumentCaptor.forClass(DiagnosticResult.class);
				Mockito.verify(resultsCollector).accept(resultCaptor.capture());
				MatcherAssert.assertThat(resultCaptor.getValue(), Matchers.instanceOf(KnownType.class));
			}

			@Test
			@DisplayName("c9r dir with dir.c9r AND symlink.c9r is ambiguous")
			public void testDirC9rAndSymlinkC9rProducesAmbiguousType() throws IOException {
				Files.createFile(c9rDir.resolve("dir.c9r"));
				Files.createFile(c9rDir.resolve("symlink.c9r"));

				visitor.checkCiphertextType(c9rDir, false);

				ArgumentCaptor<DiagnosticResult> resultCaptor = ArgumentCaptor.forClass(DiagnosticResult.class);
				Mockito.verify(resultsCollector).accept(resultCaptor.capture());
				MatcherAssert.assertThat(resultCaptor.getValue(), Matchers.instanceOf(AmbiguousType.class));
			}

			@Test
			@DisplayName("c9r dir without dir.c9r or symlink.c9r is unknown")
			public void testNoneSignatureFileProducesUnknownType() throws IOException {
				Path p = dataRoot.resolve("AA/aaaa/zaz.c9r");
				Files.createDirectories(p);

				visitor.checkCiphertextType(c9rDir, false);

				ArgumentCaptor<DiagnosticResult> resultCaptor = ArgumentCaptor.forClass(DiagnosticResult.class);
				Mockito.verify(resultsCollector).accept(resultCaptor.capture());
				MatcherAssert.assertThat(resultCaptor.getValue(), Matchers.instanceOf(UnknownType.class));
			}

			@ParameterizedTest
			@DisplayName("contents.c9r is ignored for c9r dir")
			@MethodSource("provideAllContentsC9rCombos")
			public void testContentsC9rIsIgnored(List<String> typeFiles, Class resultClass) throws IOException {
				for (var typeFile : typeFiles) {
					Files.createFile(c9rDir.resolve(typeFile));
				}

				visitor.checkCiphertextType(c9rDir, false);

				ArgumentCaptor<DiagnosticResult> resultCaptor = ArgumentCaptor.forClass(DiagnosticResult.class);
				Mockito.verify(resultsCollector).accept(resultCaptor.capture());
				MatcherAssert.assertThat(resultCaptor.getValue(), Matchers.instanceOf(resultClass));
			}

			private static List<Arguments> provideAllContentsC9rCombos() {
				return List.of( //
						Arguments.of(List.of("contents.c9r"), UnknownType.class), //
						Arguments.of(List.of("dir.c9r", "contents.c9r"), KnownType.class), //
						Arguments.of(List.of("symlink.c9r", "contents.c9r"), KnownType.class), //
						Arguments.of(List.of("dir.c9r", "symlink.c9r", "contents.c9r"), AmbiguousType.class));
			}
		}

		@Nested
		@DisplayName("Ciphertext type checks for c9s dir")
		public class C9sDirChecked {

			private Path c9sDir;

			@BeforeEach
			public void initialize() throws IOException {
				c9sDir = dataRoot.resolve("AA/pretended/c9sDir");
				Files.createDirectories(c9sDir);
			}

			@ParameterizedTest
			@DisplayName("c9s dir with only one type file is known")
			@ValueSource(strings = {"dir.c9r", "symlink.c9r", "contents.c9r"})
			public void testSignatureSymlinkFileProducesKnownType(String typeFile) throws IOException {
				Files.createFile(c9sDir.resolve(typeFile));

				visitor.checkCiphertextType(c9sDir, true);

				ArgumentCaptor<DiagnosticResult> resultCaptor = ArgumentCaptor.forClass(DiagnosticResult.class);
				Mockito.verify(resultsCollector).accept(resultCaptor.capture());
				MatcherAssert.assertThat(resultCaptor.getValue(), Matchers.instanceOf(KnownType.class));
			}

			@ParameterizedTest
			@DisplayName("c9s dir with multiple type files is ambiguous")
			@MethodSource("provideAllSigFileCombos")
			public void testMultipleSigFilesProduceAmbiguousType(List<String> typeFiles) throws IOException {
				for (var typeFile : typeFiles) {
					Files.createFile(c9sDir.resolve(typeFile));
				}

				visitor.checkCiphertextType(c9sDir, true);

				ArgumentCaptor<DiagnosticResult> resultCaptor = ArgumentCaptor.forClass(DiagnosticResult.class);
				Mockito.verify(resultsCollector).accept(resultCaptor.capture());
				MatcherAssert.assertThat(resultCaptor.getValue(), Matchers.instanceOf(AmbiguousType.class));
			}

			private static List<List<String>> provideAllSigFileCombos() {
				return List.of( //
						List.of("dir.c9r", "symlink.c9r"), //
						List.of("dir.c9r", "contents.c9r"), //
						List.of("contents.c9r", "symlink.c9r"), //
						List.of("dir.c9r", "symlink.c9r", "contents.c9r") //
				);
			}

			@Test
			@DisplayName("c9s dir without any type file is unknown")
			public void testNoneSignatureFileProducesUnknownType() throws IOException {
				Path p = dataRoot.resolve("AA/aaaa/zaz.c9s");
				Files.createDirectories(p);

				visitor.checkCiphertextType(c9sDir, true);

				ArgumentCaptor<DiagnosticResult> resultCaptor = ArgumentCaptor.forClass(DiagnosticResult.class);
				Mockito.verify(resultsCollector).accept(resultCaptor.capture());
				MatcherAssert.assertThat(resultCaptor.getValue(), Matchers.instanceOf(UnknownType.class));
			}
		}


	}
}
