package org.cryptomator.cryptofs;

import java.text.Normalizer;

import org.junit.Assert;
import org.junit.Test;
import org.mockito.Mockito;

public class CryptoPathFactoryTest {

	private final CryptoFileSystemImpl cryptoFileSystem = Mockito.mock(CryptoFileSystemImpl.class);
	private final Symlinks symlinks = Mockito.mock(Symlinks.class);
	private final CryptoPathFactory factory = new CryptoPathFactory(symlinks);

	@Test
	public void testEmptyFor() {
		CryptoPath path = factory.emptyFor(cryptoFileSystem);

		Assert.assertEquals(cryptoFileSystem, path.getFileSystem());
		Assert.assertArrayEquals(new String[0], path.getElements().toArray());
		Assert.assertFalse(path.isAbsolute());
	}

	@Test
	public void testRootFor() {
		CryptoPath path = factory.rootFor(cryptoFileSystem);

		Assert.assertEquals(cryptoFileSystem, path.getFileSystem());
		Assert.assertArrayEquals(new String[0], path.getElements().toArray());
		Assert.assertTrue(path.isAbsolute());
	}

	@Test
	public void testGetRelativePathWithSingleArgument() {
		CryptoPath path = factory.getPath(cryptoFileSystem, "foo/bar//baz");

		Assert.assertEquals(cryptoFileSystem, path.getFileSystem());
		Assert.assertArrayEquals(new String[]{"foo", "bar", "baz"}, path.getElements().toArray());
		Assert.assertFalse(path.isAbsolute());
	}

	@Test
	public void testGetAbsolutePathWithSingleArgument() {
		CryptoPath path = factory.getPath(cryptoFileSystem, "/foo/bar//baz");

		Assert.assertEquals(cryptoFileSystem, path.getFileSystem());
		Assert.assertArrayEquals(new String[]{"foo", "bar", "baz"}, path.getElements().toArray());
		Assert.assertTrue(path.isAbsolute());
	}

	@Test
	public void testGetRelativePathWithMultiArgument() {
		CryptoPath path = factory.getPath(cryptoFileSystem, "foo/bar", "//baz/foo", "bar");

		Assert.assertEquals(cryptoFileSystem, path.getFileSystem());
		Assert.assertArrayEquals(new String[]{"foo", "bar", "baz", "foo", "bar"}, path.getElements().toArray());
		Assert.assertFalse(path.isAbsolute());
	}

	@Test
	public void testGetAbsolutePathWithMultiArgument() {
		CryptoPath path = factory.getPath(cryptoFileSystem, "/foo/bar", "//baz/foo", "bar");

		Assert.assertEquals(cryptoFileSystem, path.getFileSystem());
		Assert.assertArrayEquals(new String[]{"foo", "bar", "baz", "foo", "bar"}, path.getElements().toArray());
		Assert.assertTrue(path.isAbsolute());
	}

	@Test
	public void testUnicodeNormalization() {
		String nfcChar = Normalizer.normalize("ü", Normalizer.Form.NFC);
		String nfdChar = Normalizer.normalize("ü", Normalizer.Form.NFD);
		Assert.assertNotEquals(nfcChar, nfdChar);

		CryptoPath path = factory.getPath(cryptoFileSystem, nfdChar, nfdChar, nfcChar);

		Assert.assertArrayEquals(new String[]{nfcChar, nfcChar, nfcChar}, path.getElements().toArray());
	}

}
