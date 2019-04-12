package org.cryptomator.cryptofs;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.text.Normalizer;

public class CryptoPathFactoryTest {

	private final CryptoFileSystemImpl cryptoFileSystem = Mockito.mock(CryptoFileSystemImpl.class);
	private final Symlinks symlinks = Mockito.mock(Symlinks.class);
	private final CryptoPathFactory factory = new CryptoPathFactory(symlinks);

	@Test
	public void testEmptyFor() {
		CryptoPath path = factory.emptyFor(cryptoFileSystem);

		Assertions.assertEquals(cryptoFileSystem, path.getFileSystem());
		Assertions.assertArrayEquals(new String[0], path.getElements().toArray());
		Assertions.assertFalse(path.isAbsolute());
	}

	@Test
	public void testRootFor() {
		CryptoPath path = factory.rootFor(cryptoFileSystem);

		Assertions.assertEquals(cryptoFileSystem, path.getFileSystem());
		Assertions.assertArrayEquals(new String[0], path.getElements().toArray());
		Assertions.assertTrue(path.isAbsolute());
	}

	@Test
	public void testGetRelativePathWithSingleArgument() {
		CryptoPath path = factory.getPath(cryptoFileSystem, "foo/bar//baz");

		Assertions.assertEquals(cryptoFileSystem, path.getFileSystem());
		Assertions.assertArrayEquals(new String[]{"foo", "bar", "baz"}, path.getElements().toArray());
		Assertions.assertFalse(path.isAbsolute());
	}

	@Test
	public void testGetAbsolutePathWithSingleArgument() {
		CryptoPath path = factory.getPath(cryptoFileSystem, "/foo/bar//baz");

		Assertions.assertEquals(cryptoFileSystem, path.getFileSystem());
		Assertions.assertArrayEquals(new String[]{"foo", "bar", "baz"}, path.getElements().toArray());
		Assertions.assertTrue(path.isAbsolute());
	}

	@Test
	public void testGetRelativePathWithMultiArgument() {
		CryptoPath path = factory.getPath(cryptoFileSystem, "foo/bar", "//baz/foo", "bar");

		Assertions.assertEquals(cryptoFileSystem, path.getFileSystem());
		Assertions.assertArrayEquals(new String[]{"foo", "bar", "baz", "foo", "bar"}, path.getElements().toArray());
		Assertions.assertFalse(path.isAbsolute());
	}

	@Test
	public void testGetAbsolutePathWithMultiArgument() {
		CryptoPath path = factory.getPath(cryptoFileSystem, "/foo/bar", "//baz/foo", "bar");

		Assertions.assertEquals(cryptoFileSystem, path.getFileSystem());
		Assertions.assertArrayEquals(new String[]{"foo", "bar", "baz", "foo", "bar"}, path.getElements().toArray());
		Assertions.assertTrue(path.isAbsolute());
	}

	@Test
	public void testUnicodeNormalization() {
		String nfcChar = Normalizer.normalize("ü", Normalizer.Form.NFC);
		String nfdChar = Normalizer.normalize("ü", Normalizer.Form.NFD);
		Assertions.assertNotEquals(nfcChar, nfdChar);

		CryptoPath path = factory.getPath(cryptoFileSystem, nfdChar, nfdChar, nfcChar);

		Assertions.assertArrayEquals(new String[]{nfcChar, nfcChar, nfcChar}, path.getElements().toArray());
	}

}
