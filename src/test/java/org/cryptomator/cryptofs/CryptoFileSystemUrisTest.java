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

	@Test
	public void testParseValidUri() throws URISyntaxException {
		Path path = Paths.get("a").toAbsolutePath();
		ParsedUri parsed = CryptoFileSystemUris.parseUri(new URI("cryptomator", path.toUri().toString(), "/b", null, null));

		assertThat(parsed.pathToVault(), is(path));
		assertThat(parsed.pathInsideVault(), is("/b"));
	}

	@Test
	public void testParseUriWithInvalidScheme() throws URISyntaxException {
		Path path = Paths.get("a").toAbsolutePath();

		thrown.expect(IllegalArgumentException.class);

		CryptoFileSystemUris.parseUri(new URI("invalid", path.toUri().toString(), "/b", null, null));
	}

	@Test
	public void testParseUriWithoutAuthority() throws URISyntaxException {
		thrown.expect(IllegalArgumentException.class);

		CryptoFileSystemUris.parseUri(new URI("cryptomator", null, "/b", null, null));
	}

	@Test
	public void testParseUriWithoutPath() throws URISyntaxException {
		System.out.println(Paths.get("a").toUri().toString());
		Path path = Paths.get("a").toAbsolutePath();

		thrown.expect(IllegalArgumentException.class);

		CryptoFileSystemUris.parseUri(new URI("cryptomator", path.toUri().toString(), null, null, null));
	}

	@Test
	public void testParseUriWithQuery() throws URISyntaxException {
		Path path = Paths.get("a").toAbsolutePath();

		thrown.expect(IllegalArgumentException.class);

		CryptoFileSystemUris.parseUri(new URI("cryptomator", path.toUri().toString(), "/b", "a=b", null));
	}

	@Test
	public void testParseUriWithFragment() throws URISyntaxException {
		Path path = Paths.get("a").toAbsolutePath();

		thrown.expect(IllegalArgumentException.class);

		CryptoFileSystemUris.parseUri(new URI("cryptomator", path.toUri().toString(), "/b", null, "abc"));
	}

	@Test
	public void testURIConstructorDoesNotThrowExceptionForNonServerBasedAuthority() throws URISyntaxException {
		// The constructor states that a URISyntaxException is thrown if a registry based authority is used.
		// The implementation tells that it doesn't. Assume it works but ensure that this test tells us if
		// the implementation changes.
		new URI("scheme", Paths.get("test").toUri().toString(), "/b", null, null);
	}

}
