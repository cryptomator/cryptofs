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

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

public class CryptoFileSystemUriTest {

	@Rule
	public ExpectedException thrown = ExpectedException.none();

	@Test
	public void testUncCompatibleUriToPathWithUncSslUri() throws URISyntaxException {
		URI uri = URI.create("file://webdavserver.com@SSL/DavWWWRoot/User7ff2b01/asd/");

		Path path = CryptoFileSystemUri.uncCompatibleUriToPath(uri);

		assertThat(path, is(Paths.get("\\\\webdavserver.com@SSL\\DavWWWRoot\\User7ff2b01\\asd\\")));
	}

	@Test
	public void testUncCompatibleUriToPathWithUncSslAndPortUri() throws URISyntaxException {
		URI uri = URI.create("file://webdavserver.com@SSL@123/DavWWWRoot/User7ff2b01/asd/");

		Path path = CryptoFileSystemUri.uncCompatibleUriToPath(uri);

		assertThat(path, is(Paths.get("\\\\webdavserver.com@SSL@123\\DavWWWRoot\\User7ff2b01\\asd\\")));
	}

	@Test
	public void testUncCompatibleUriToPathWithNormalUri() throws URISyntaxException {
		URI uri = URI.create("file:///normal/file/path/");

		Path path = CryptoFileSystemUri.uncCompatibleUriToPath(uri);

		assertThat(path, is(Paths.get("/normal/file/path")));
	}

	@Test
	public void testCreateWithoutPathComponents() {
		Path absolutePathToVault = Paths.get("a").toAbsolutePath();

		URI uri = CryptoFileSystemUri.create(absolutePathToVault);
		CryptoFileSystemUri parsed = CryptoFileSystemUri.parse(uri);

		assertThat(parsed.pathToVault(), is(absolutePathToVault));
		assertThat(parsed.pathInsideVault(), is("/"));
	}

	@Test
	public void testCreateWithPathComponents() throws URISyntaxException {
		Path absolutePathToVault = Paths.get("c").toAbsolutePath();

		URI uri = CryptoFileSystemUri.create(absolutePathToVault, "a", "b", "c");
		System.out.println(uri);
		CryptoFileSystemUri parsed = CryptoFileSystemUri.parse(uri);

		assertThat(parsed.pathToVault(), is(absolutePathToVault));
		assertThat(parsed.pathInsideVault(), is("/a/b/c"));
	}

	@Test
	public void testCreateWithPathToVaultFromNonDefaultProvider() throws IOException {
		Path tempDir = createTempDirectory("CryptoFileSystemUrisTest").toAbsolutePath();
		try {
			FileSystem fileSystem = CryptoFileSystemProvider.newFileSystem(tempDir, cryptoFileSystemProperties().withPassphrase("asd").build());
			Path absolutePathToVault = fileSystem.getPath("a").toAbsolutePath();

			URI uri = CryptoFileSystemUri.create(absolutePathToVault, "a", "b");
			CryptoFileSystemUri parsed = CryptoFileSystemUri.parse(uri);

			assertThat(parsed.pathToVault(), is(absolutePathToVault));
			assertThat(parsed.pathInsideVault(), is("/a/b"));
		} finally {
			Files.walkFileTree(tempDir, new DeletingFileVisitor());
		}
	}

	@Test
	public void testCreateWithNonAbsolutePathUsesAbsolutePath() {
		Path nonAbsolutePathToVault = Paths.get("c");
		Path absolutePathToVault = nonAbsolutePathToVault.toAbsolutePath();

		URI uri = CryptoFileSystemUri.create(nonAbsolutePathToVault);
		CryptoFileSystemUri parsed = CryptoFileSystemUri.parse(uri);

		assertThat(parsed.pathToVault(), is(absolutePathToVault));
		assertThat(parsed.pathInsideVault(), is("/"));
	}

	@Test
	public void testParseValidUri() throws URISyntaxException {
		Path path = Paths.get("a").toAbsolutePath();
		CryptoFileSystemUri parsed = CryptoFileSystemUri.parse(new URI("cryptomator", path.toUri().toString(), "/b", null, null));

		assertThat(parsed.pathToVault(), is(path));
		assertThat(parsed.pathInsideVault(), is("/b"));
	}

	@Test
	public void testParseWithInvalidScheme() throws URISyntaxException {
		Path path = Paths.get("a").toAbsolutePath();

		thrown.expect(IllegalArgumentException.class);

		CryptoFileSystemUri.parse(new URI("invalid", path.toUri().toString(), "/b", null, null));
	}

	@Test
	public void testParseWithoutAuthority() throws URISyntaxException {
		thrown.expect(IllegalArgumentException.class);

		CryptoFileSystemUri.parse(new URI("cryptomator", null, "/b", null, null));
	}

	@Test
	public void testParseWithoutPath() throws URISyntaxException {
		Path path = Paths.get("a").toAbsolutePath();

		thrown.expect(IllegalArgumentException.class);

		CryptoFileSystemUri.parse(new URI("cryptomator", path.toUri().toString(), null, null, null));
	}

	@Test
	public void testParseWithQuery() throws URISyntaxException {
		Path path = Paths.get("a").toAbsolutePath();

		thrown.expect(IllegalArgumentException.class);

		CryptoFileSystemUri.parse(new URI("cryptomator", path.toUri().toString(), "/b", "a=b", null));
	}

	@Test
	public void testParseWithFragment() throws URISyntaxException {
		Path path = Paths.get("a").toAbsolutePath();

		thrown.expect(IllegalArgumentException.class);

		CryptoFileSystemUri.parse(new URI("cryptomator", path.toUri().toString(), "/b", null, "abc"));
	}

	@Test
	public void testURIConstructorDoesNotThrowExceptionForNonServerBasedAuthority() throws URISyntaxException {
		// The constructor states that a URISyntaxException is thrown if a registry based authority is used.
		// The implementation tells that it doesn't. Assume it works but ensure that this test tells us if
		// the implementation changes.
		new URI("scheme", Paths.get("test").toUri().toString(), "/b", null, null);
	}

}
