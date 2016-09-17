package org.cryptomator.cryptofs;

import static java.nio.file.Files.createTempDirectory;
import static org.cryptomator.cryptofs.CryptoFileSystemProperties.cryptoFileSystemProperties;
import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.file.FileSystem;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import org.cryptomator.cryptofs.CryptoFileSystemUris.ParsedUri;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

public class CryptoFileSystemUrisTest {

	@Rule
	public ExpectedException thrown = ExpectedException.none();

	@Test
	public void testCreateUriWithoutPathComponents() {
		Path absolutePathToVault = Paths.get("a").toAbsolutePath();

		URI uri = CryptoFileSystemUris.createUri(absolutePathToVault);
		ParsedUri parsed = CryptoFileSystemUris.parseUri(uri);

		assertThat(parsed.pathToVault(), is(absolutePathToVault));
		assertThat(parsed.pathInsideVault(), is("/"));
	}

	@Test
	public void testCreateUriWithPathComponents() throws URISyntaxException {
		Path absolutePathToVault = Paths.get("c").toAbsolutePath();

		URI uri = CryptoFileSystemUris.createUri(absolutePathToVault, "a", "b", "c");
		ParsedUri parsed = CryptoFileSystemUris.parseUri(uri);

		assertThat(parsed.pathToVault(), is(absolutePathToVault));
		assertThat(parsed.pathInsideVault(), is("/a/b/c"));
	}

	@Test
	public void testCreateUriWithPathToVaultFromNonDefaultProvider() throws IOException {
		Path tempDir = createTempDirectory("CryptoFileSystemUrisTest").toAbsolutePath();
		try {
			FileSystem fileSystem = CryptoFileSystemProvider.newFileSystem(tempDir, cryptoFileSystemProperties().withPassphrase("asd").build());
			Path absolutePathToVault = fileSystem.getPath("a").toAbsolutePath();

			URI uri = CryptoFileSystemUris.createUri(absolutePathToVault, "a", "b");
			ParsedUri parsed = CryptoFileSystemUris.parseUri(uri);

			assertThat(parsed.pathToVault(), is(absolutePathToVault));
			assertThat(parsed.pathInsideVault(), is("/a/b"));
		} finally {
			Files.walkFileTree(tempDir, new DeletingFileVisitor());
		}
	}

	@Test
	public void testCreateUriWithNonAbsolutePathUsesAbsolutePath() {
		Path nonAbsolutePathToVault = Paths.get("c");
		Path absolutePathToVault = nonAbsolutePathToVault.toAbsolutePath();

		URI uri = CryptoFileSystemUris.createUri(nonAbsolutePathToVault);
		ParsedUri parsed = CryptoFileSystemUris.parseUri(uri);

		assertThat(parsed.pathToVault(), is(absolutePathToVault));
		assertThat(parsed.pathInsideVault(), is("/"));
	}

}
