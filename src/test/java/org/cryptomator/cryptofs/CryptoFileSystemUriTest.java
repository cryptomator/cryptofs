package org.cryptomator.cryptofs;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.file.FileSystem;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import static java.nio.file.Files.createTempDirectory;
import static org.cryptomator.cryptofs.CryptoFileSystemProperties.cryptoFileSystemProperties;

public class CryptoFileSystemUriTest {

	@Test
	public void testUncCompatibleUriToPathWithUncSslUri() throws URISyntaxException {
		URI uri = URI.create("file://webdavserver.com@SSL/DavWWWRoot/User7ff2b01/asd/");

		Path path = CryptoFileSystemUri.uncCompatibleUriToPath(uri);

		Assertions.assertEquals(Paths.get("\\\\webdavserver.com@SSL\\DavWWWRoot\\User7ff2b01\\asd\\"), path);
	}

	@Test
	public void testUncCompatibleUriToPathWithUncSslAndPortUri() throws URISyntaxException {
		URI uri = URI.create("file://webdavserver.com@SSL@123/DavWWWRoot/User7ff2b01/asd/");

		Path path = CryptoFileSystemUri.uncCompatibleUriToPath(uri);

		Assertions.assertEquals(Paths.get("\\\\webdavserver.com@SSL@123\\DavWWWRoot\\User7ff2b01\\asd\\"), path);
	}

	@Test
	public void testUncCompatibleUriToPathWithNormalUri() throws URISyntaxException {
		URI uri = URI.create("file:///normal/file/path/");

		Path path = CryptoFileSystemUri.uncCompatibleUriToPath(uri);

		Assertions.assertEquals(Paths.get("/normal/file/path"), path);
	}

	@Test
	public void testCreateWithoutPathComponents() {
		Path absolutePathToVault = Paths.get("a").toAbsolutePath();

		URI uri = CryptoFileSystemUri.create(absolutePathToVault);
		CryptoFileSystemUri parsed = CryptoFileSystemUri.parse(uri);

		Assertions.assertEquals(absolutePathToVault, parsed.pathToVault());
		Assertions.assertEquals("/", parsed.pathInsideVault());
	}

	@Test
	public void testCreateWithPathComponents() throws URISyntaxException {
		Path absolutePathToVault = Paths.get("c").toAbsolutePath();

		URI uri = CryptoFileSystemUri.create(absolutePathToVault, "a", "b", "c");
		System.out.println(uri);
		CryptoFileSystemUri parsed = CryptoFileSystemUri.parse(uri);

		Assertions.assertEquals(absolutePathToVault, parsed.pathToVault());
		Assertions.assertEquals("/a/b/c", parsed.pathInsideVault());
	}

	@Test
	public void testCreateWithPathToVaultFromNonDefaultProvider() throws IOException {
		Path tempDir = createTempDirectory("CryptoFileSystemUrisTest").toAbsolutePath();
		try {
			FileSystem fileSystem = CryptoFileSystemProvider.newFileSystem(tempDir, cryptoFileSystemProperties().withPassphrase("asd").build());
			Path absolutePathToVault = fileSystem.getPath("a").toAbsolutePath();

			URI uri = CryptoFileSystemUri.create(absolutePathToVault, "a", "b");
			CryptoFileSystemUri parsed = CryptoFileSystemUri.parse(uri);

			Assertions.assertEquals(absolutePathToVault, parsed.pathToVault());
			Assertions.assertEquals("/a/b", parsed.pathInsideVault());
		} finally {
			Files.walkFileTree(tempDir, DeletingFileVisitor.INSTANCE);
		}
	}

	@Test
	public void testCreateWithNonAbsolutePathUsesAbsolutePath() {
		Path nonAbsolutePathToVault = Paths.get("c");
		Path absolutePathToVault = nonAbsolutePathToVault.toAbsolutePath();

		URI uri = CryptoFileSystemUri.create(nonAbsolutePathToVault);
		CryptoFileSystemUri parsed = CryptoFileSystemUri.parse(uri);

		Assertions.assertEquals(absolutePathToVault, parsed.pathToVault());
		Assertions.assertEquals("/", parsed.pathInsideVault());
	}

	@Test
	public void testParseValidUri() throws URISyntaxException {
		Path path = Paths.get("a").toAbsolutePath();
		CryptoFileSystemUri parsed = CryptoFileSystemUri.parse(new URI("cryptomator", path.toUri().toString(), "/b", null, null));

		Assertions.assertEquals(path, parsed.pathToVault());
		Assertions.assertEquals("/b", parsed.pathInsideVault());
	}

	@Test
	public void testParseWithInvalidScheme() {
		Path path = Paths.get("a").toAbsolutePath();

		Assertions.assertThrows(IllegalArgumentException.class, () -> {
			CryptoFileSystemUri.parse(new URI("invalid", path.toUri().toString(), "/b", null, null));
		});
	}

	@Test
	public void testParseWithoutAuthority() {
		Assertions.assertThrows(IllegalArgumentException.class, () -> {
			CryptoFileSystemUri.parse(new URI("cryptomator", null, "/b", null, null));
		});
	}

	@Test
	public void testParseWithoutPath() {
		Path path = Paths.get("a").toAbsolutePath();

		Assertions.assertThrows(IllegalArgumentException.class, () -> {
			CryptoFileSystemUri.parse(new URI("cryptomator", path.toUri().toString(), null, null, null));
		});
	}

	@Test
	public void testParseWithQuery() {
		Path path = Paths.get("a").toAbsolutePath();

		Assertions.assertThrows(IllegalArgumentException.class, () -> {
			CryptoFileSystemUri.parse(new URI("cryptomator", path.toUri().toString(), "/b", "a=b", null));
		});
	}

	@Test
	public void testParseWithFragment() {
		Path path = Paths.get("a").toAbsolutePath();

		Assertions.assertThrows(IllegalArgumentException.class, () -> {
			CryptoFileSystemUri.parse(new URI("cryptomator", path.toUri().toString(), "/b", null, "abc"));
		});
	}

	@Test
	public void testURIConstructorDoesNotThrowExceptionForNonServerBasedAuthority() throws URISyntaxException {
		// The constructor states that a URISyntaxException is thrown if a registry based authority is used.
		// The implementation tells that it doesn't. Assume it works but ensure that this test tells us if
		// the implementation changes.
		new URI("scheme", Paths.get("test").toUri().toString(), "/b", null, null);
	}

}
