package org.cryptomator.cryptofs.health.shortened;

import com.google.common.jimfs.Configuration;
import com.google.common.jimfs.Jimfs;
import org.cryptomator.cryptofs.health.api.DiagnosticResult;
import org.cryptomator.cryptofs.health.dirid.DirIdCheck;
import org.cryptomator.cryptolib.api.Cryptor;
import org.cryptomator.cryptolib.api.FileNameCryptor;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.mockito.Mockito;

import java.io.IOException;
import java.nio.file.FileSystem;
import java.nio.file.Path;
import java.util.function.Consumer;

public class ShortenedNamesCheckTest {

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

		Mockito.when(cryptor.fileNameCryptor()).thenReturn(fileNameCryptor);
		Mockito.when(fileNameCryptor.hashDirectoryId(Mockito.any())).then(i -> i.getArgument(0));
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

	}
}
