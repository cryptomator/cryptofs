package org.cryptomator.cryptofs.health.shortened;

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
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileSystem;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.Set;
import java.util.function.Consumer;

import static org.cryptomator.cryptofs.health.shortened.ShortenedNamesCheck.DirVisitor.SyntaxResult.VALID;

public class ShortenedNamesCheckTest {

	private FileSystem fs;
	private Path dataRoot;

	@BeforeEach
	public void setup() {
		fs = Jimfs.newFileSystem(Configuration.unix());
		dataRoot = fs.getPath("/d");
	}

	@AfterEach
	public void teardown() throws IOException {
		fs.close();
	}

	@Nested
	@DisplayName("DirVisitor")
	public class Visitor {

		private Consumer<DiagnosticResult> resultsCollector;
		private ShortenedNamesCheck.DirVisitor visitor;

		@BeforeEach
		public void setup() {
			resultsCollector = Mockito.mock(Consumer.class);
			visitor = new ShortenedNamesCheck.DirVisitor(resultsCollector);
		}

		@Test
		@DisplayName("dirs ending with c9s are visited and closer looked at")
		public void testC9sDirsAreVisited() throws IOException {
			Path p = dataRoot.resolve("AA/zzzz/bar=.c9s");
			Files.createDirectories(p);

			var visitorSpy = Mockito.spy(visitor);
			Files.walkFileTree(dataRoot, Set.of(), 3, visitorSpy);

			Mockito.verify(visitorSpy).visitFile(Mockito.eq(p), Mockito.any());
			Mockito.verify(visitorSpy).checkShortenedName(p);
		}

		@Test
		@DisplayName("dir with name.c9s and matching long/short names produces valid result")
		public void testExistingNamesFileAndMatchingNamesProducesValidResult() throws IOException {
			String longName = "veryLongButNotTooLongName";
			Path dir = dataRoot.resolve("AA/zzzz/shortName.c9s");
			Path nameFile = dir.resolve("name.c9s");
			Files.createDirectories(dir);
			Files.writeString(nameFile, longName, StandardCharsets.UTF_8, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE);

			var visitorSpy = Mockito.spy(visitor);
			Mockito.doReturn("shortName.c9s").when(visitorSpy).deflate(longName);
			Mockito.doReturn(VALID).when(visitorSpy).checkSyntax(longName);

			visitorSpy.checkShortenedName(dir);
			ArgumentCaptor<DiagnosticResult> resultCaptor = ArgumentCaptor.forClass(DiagnosticResult.class);
			Mockito.verify(resultsCollector).accept(resultCaptor.capture());
			MatcherAssert.assertThat(resultCaptor.getValue(), Matchers.instanceOf(ValidShortenedFile.class));
		}

		@Test
		@DisplayName("dir with missing name.c9s produces missing result")
		public void testMissingNamesFileProducesMissingResult() throws IOException {
			Path dir = dataRoot.resolve("AA/zzzz/shortName.c9s");
			Files.createDirectories(dir);

			visitor.checkShortenedName(dir);
			ArgumentCaptor<DiagnosticResult> resultCaptor = ArgumentCaptor.forClass(DiagnosticResult.class);
			Mockito.verify(resultsCollector).accept(resultCaptor.capture());
			MatcherAssert.assertThat(resultCaptor.getValue(), Matchers.instanceOf(MissingLongName.class));
		}

		@Test
		@DisplayName("dir with too big name.c9s produces obese result")
		public void testTooBigNamesFileProducesObeseResult() throws IOException {
			Path dir = dataRoot.resolve("AA/zzzz/shortName.c9s");
			Path obeseFile = dir.resolve("name.c9s");
			Files.createDirectories(dir);
			byte[] content = new byte[1024];
			try (var ch = Files.newByteChannel(obeseFile, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE)) {
				//truncate is no-op on jimFs RegularFile
				for (int i = 0; i < 11; i++) {
					ch.write(ByteBuffer.wrap(content));
				}
			}

			visitor.checkShortenedName(dir);
			ArgumentCaptor<DiagnosticResult> resultCaptor = ArgumentCaptor.forClass(DiagnosticResult.class);
			Mockito.verify(resultsCollector).accept(resultCaptor.capture());
			MatcherAssert.assertThat(resultCaptor.getValue(), Matchers.instanceOf(ObeseNameFile.class));
		}

		@Test
		@DisplayName("dir with mismatching long and short names produces mismatch result")
		public void testMismatchingNamesProducesMismatchResult() throws IOException {
			String longName = "veryLongButNotTooLongName";
			Path dir = dataRoot.resolve("AA/zzzz/shortName.c9s");
			Path nameFile = dir.resolve("name.c9s");
			Files.createDirectories(dir);
			Files.writeString(nameFile, longName, StandardCharsets.UTF_8, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE);

			var visitorSpy = Mockito.spy(visitor);
			Mockito.doReturn("otherName.c9s").when(visitorSpy).deflate(longName);
			Mockito.doReturn(VALID).when(visitorSpy).checkSyntax(longName);

			visitorSpy.checkShortenedName(dir);
			ArgumentCaptor<DiagnosticResult> resultCaptor = ArgumentCaptor.forClass(DiagnosticResult.class);
			Mockito.verify(resultsCollector).accept(resultCaptor.capture());
			MatcherAssert.assertThat(resultCaptor.getValue(), Matchers.instanceOf(LongShortNamesMismatch.class));
		}

		@Test
		@DisplayName("dir with non base64url content in name.c9s produces illegal encoding result")
		public void testNonBase64URLCharsInNameFileProducesIllegalEncodingResult() throws IOException {
			String longName = "Bug##121\0\0\0";
			Path dir = dataRoot.resolve("AA/zzzz/shortName.c9s");
			Path nameFile = dir.resolve("name.c9s");
			Files.createDirectories(dir);
			Files.writeString(nameFile, longName, StandardCharsets.UTF_8, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE);

			visitor.checkShortenedName(dir);
			ArgumentCaptor<DiagnosticResult> resultCaptor = ArgumentCaptor.forClass(DiagnosticResult.class);
			Mockito.verify(resultsCollector).accept(resultCaptor.capture());
			MatcherAssert.assertThat(resultCaptor.getValue(), Matchers.instanceOf(NotDecodableLongName.class));
		}

		@Test
		@DisplayName("dir with non base64url content in name.c9s produces illegal encoding result")
		public void testNameFileWithTrailingNullBytesProducesIllegalEncodingResult() throws IOException {
			String longName = "VGhpc0lzQVRlc3Q.c9r\0\0\u0002\0"; //" base64url("ThisIsATest") + ".c9r" + "\0\0\0"

			Path dir = dataRoot.resolve("AA/zzzz/shortName.c9s");
			Path nameFile = dir.resolve("name.c9s");
			Files.createDirectories(dir);
			Files.writeString(nameFile, longName, StandardCharsets.UTF_8, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE);

			visitor.checkShortenedName(dir);
			ArgumentCaptor<DiagnosticResult> resultCaptor = ArgumentCaptor.forClass(DiagnosticResult.class);
			Mockito.verify(resultsCollector).accept(resultCaptor.capture());
			MatcherAssert.assertThat(resultCaptor.getValue(), Matchers.instanceOf(TrailingBytesInNameFile.class));
		}

	}
}
