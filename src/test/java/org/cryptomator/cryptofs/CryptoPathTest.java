/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptofs;

import static java.util.Arrays.asList;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.sameInstance;
import static org.hamcrest.Matchers.comparesEqualTo;
import static org.hamcrest.Matchers.greaterThan;
import static org.hamcrest.Matchers.lessThan;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThat;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.file.FileSystems;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.ProviderMismatchException;
import java.nio.file.WatchEvent;
import java.nio.file.WatchService;
import java.util.Arrays;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.junit.runner.RunWith;
import org.mockito.Mockito;

import com.google.common.collect.Lists;

import de.bechte.junit.runners.context.HierarchicalContextRunner;

@RunWith(HierarchicalContextRunner.class)
public class CryptoPathTest {

	@Rule
	public final ExpectedException thrown = ExpectedException.none();

	private CryptoFileSystem fileSystem;

	private CryptoPathFactory cryptoPathFactory = new CryptoPathFactory();

	private CryptoPath rootPath;
	private CryptoPath emptyPath;

	@Before
	public void setup() {
		fileSystem = Mockito.mock(CryptoFileSystem.class);
		rootPath = cryptoPathFactory.rootFor(fileSystem);
		emptyPath = cryptoPathFactory.emptyFor(fileSystem);
		when(fileSystem.getPath(any(String.class))).thenAnswer(invocation -> {
			String first = invocation.getArgumentAt(0, String.class);
			return path(first);
		});

		when(fileSystem.getRootPath()).thenReturn(rootPath);
		when(fileSystem.getEmptyPath()).thenReturn(emptyPath);
	}

	@Test
	public void testIsAbsolute() {
		Path p1 = path("/foo/bar");
		Path p2 = path("foo/bar");
		Assert.assertTrue(p1.isAbsolute());
		Assert.assertFalse(p2.isAbsolute());
	}

	@Test
	public void testStartsWith() {
		Path p1 = path("/foo/bar");
		Path p2 = path("/foo");
		Path p3 = path("foo/bar");
		Path p4 = path("foo");

		Assert.assertTrue(p1.startsWith(p1));
		Assert.assertTrue(p1.startsWith(p2));
		Assert.assertTrue(p1.startsWith("/foo"));
		Assert.assertFalse(p1.startsWith("/fo"));
		Assert.assertFalse(p2.startsWith(p1));
		Assert.assertFalse(p1.startsWith(p3));
		Assert.assertFalse(p1.startsWith(p4));
		Assert.assertTrue(p3.startsWith("foo"));
		Assert.assertTrue(p3.startsWith(p4));
		Assert.assertFalse(p4.startsWith(p3));
	}

	@Test
	public void testEndsWith() {

		Path p1 = path("/foo/bar");
		Path p2 = path("bar");
		Assert.assertTrue(p1.endsWith(p1));
		Assert.assertTrue(p1.endsWith(p2));
		Assert.assertTrue(p1.endsWith("bar"));
		Assert.assertTrue(p1.endsWith("foo/bar"));
		Assert.assertTrue(p1.endsWith("/foo/bar"));
		Assert.assertFalse(p1.endsWith("ba"));
		Assert.assertFalse(p1.endsWith("/foo/bar/baz"));
	}

	@Test
	public void testGetParent() {
		Path p1 = path("/foo");
		Path p2 = path("/foo/bar");
		Path p3 = path("foo");

		Assert.assertEquals(p1, p2.getParent());
		Assert.assertEquals(rootPath, p1.getParent());
		Assert.assertNull(emptyPath.getParent());
		Assert.assertNull(p3.getParent());
	}

	@Test
	public void testToString() {
		Path p1 = path("/foo/bar");
		Path p2 = path("foo/bar");
		Assert.assertEquals("/foo/bar", p1.toString());
		Assert.assertEquals("foo/bar", p2.toString());
	}

	@Test
	public void testNormalize() {
		Path p = path("/../../foo/bar/.///../baz").normalize();
		Assert.assertEquals("/../../foo/baz", p.toString());
	}

	@Test
	public void testToUri() throws URISyntaxException {
		Path pathToVault = mock(Path.class);
		when(pathToVault.isAbsolute()).thenReturn(true);
		when(fileSystem.getPathToVault()).thenReturn(pathToVault);

		URI uri = path("/foo/bar").toUri();

		assertEquals(new URI("cryptomator", null, "/" + pathToVault.toString(), "/foo/bar"), uri);
	}

	@Test
	public void testEquality() {
		Path p1 = path("/foo");
		Assert.assertNotEquals(p1, null);
		Assert.assertNotEquals(p1, "string");

		Path p2 = path("/foo");
		Assert.assertEquals(p1.hashCode(), p2.hashCode());
		Assert.assertEquals(p1, p2);

		Path p3 = path("foo");
		Assert.assertNotEquals(p1, p3);

		Path p4 = p3.resolve("bar");
		Path p5 = path("foo/bar");
		Assert.assertEquals(p4.hashCode(), p5.hashCode());
		Assert.assertEquals(p4, p5);

		Path p6 = p1.resolve("bar");
		Path p7 = p1.resolveSibling("foo/bar");
		Assert.assertEquals(p6.hashCode(), p7.hashCode());
		Assert.assertEquals(p6, p7);
	}

	@Test
	public void testRegisterWithThreeParamsThrowsUnsupportedOperationException() throws IOException {
		WatchService irrelevantWatcher = null;
		WatchEvent.Kind<?>[] irrelevantWatchEvents = null;
		WatchEvent.Modifier[] irrelevantModifiers = null;

		thrown.expect(UnsupportedOperationException.class);

		rootPath.register(irrelevantWatcher, irrelevantWatchEvents, irrelevantModifiers);
	}

	@Test
	public void testRegisterWithTwoParamsThrowsUnsupportedOperationException() throws IOException {
		WatchService irrelevantWatcher = null;
		WatchEvent.Kind<?>[] irrelevantWatchEvents = null;

		thrown.expect(UnsupportedOperationException.class);

		rootPath.register(irrelevantWatcher, irrelevantWatchEvents);
	}

	@Test
	public void testIterator() {
		Path p = path("/foo/bar/baz");
		Assert.assertArrayEquals(Arrays.asList("foo", "bar", "baz").toArray(), Lists.newArrayList(p.iterator()).stream().map(Path::toString).toArray());
	}

	@Test
	public void testGetFileName() {
		Path p = path("/foo/bar/baz");
		Path name = p.getFileName();
		Assert.assertEquals(path("baz"), name);
		Assert.assertNull(emptyPath.getFileName());
	}

	@Test
	public void testGetRootForAbsolutePath() {
		CryptoPath path = new CryptoPath(fileSystem, asList("a"), true);

		assertThat(path.getRoot(), is(rootPath));
	}

	@Test
	public void testGetRootForNonAbsolutePath() {
		CryptoPath path = new CryptoPath(fileSystem, asList("a"), false);

		assertThat(path.getRoot(), is(nullValue()));
	}

	@Test
	public void testToAbsolutePathReturnsThisIfAlreadyAbsolute() {
		Path inTest = new CryptoPath(fileSystem, asList("a", "b"), true);

		assertThat(inTest.toAbsolutePath(), is(sameInstance(inTest)));
	}

	@Test
	public void testToAbsolutePathReturnsAbsolutePathIfNotAlreadyAbsolute() {
		Path inTest = new CryptoPath(fileSystem, asList("a", "b"), false);
		Path absolutePath = new CryptoPath(fileSystem, asList("a", "b"), true);

		assertThat(inTest.toAbsolutePath(), is(absolutePath));
	}

	@Test
	public void testToRealPathReturnsThisIfAlreadyAbsolute() throws IOException {
		Path inTest = new CryptoPath(fileSystem, asList("a", "b"), true);

		assertThat(inTest.toRealPath(), is(sameInstance(inTest)));
	}

	@Test
	public void testToRealPathReturnsAbsolutePathIfNotAlreadyAbsolute() throws IOException {
		Path inTest = new CryptoPath(fileSystem, asList("a", "b"), false);
		Path absolutePath = new CryptoPath(fileSystem, asList("a", "b"), true);

		assertThat(inTest.toRealPath(), is(absolutePath));
	}

	@Test
	public void testToFileThrowsUnsupportedOperationException() {
		thrown.expect(UnsupportedOperationException.class);

		new CryptoPath(fileSystem, asList("a"), true).toFile();
	}

	@Test
	public void testGetFileSystemReturnsFileSystem() {
		Path inTest = new CryptoPath(fileSystem, asList("a"), false);

		assertThat(inTest.getFileSystem(), is(fileSystem));
	}

	public class ResolveTest {

		@Test
		public void testResolve() {
			Path p1 = path("/foo");
			Path p2 = p1.resolve("bar");
			Assert.assertEquals(path("/foo/bar"), p2);

			Path p3 = path("foo");
			Path p4 = p3.resolve("bar");
			Assert.assertEquals(path("foo/bar"), p4);

			Path p5 = path("/abs/path");
			Path p6 = p4.resolve(p5);
			Assert.assertEquals(p5, p6);
		}

		@Test
		public void testResolveSiblingReturnsOtherWhenPathHasNoParent() {
			Path pathWithoutParent = new CryptoPath(fileSystem, asList("a"), false);
			Path other = new CryptoPath(fileSystem, asList("b"), false);

			assertThat(pathWithoutParent.resolveSibling(other), is(other));
		}

		@Test
		public void testResolveSiblingReturnsOtherWhenOtherIsAbsolute() {
			Path pathWithParent = new CryptoPath(fileSystem, asList("a", "b"), true);
			Path other = new CryptoPath(fileSystem, asList("b"), true);

			assertThat(pathWithParent.resolveSibling(other), is(other));
		}

		@Test
		public void testResolveSiblingReturnsOtherWhenOtherIsAbsoluteAndPathHasNoParent() {
			Path pathWithoutParent = new CryptoPath(fileSystem, asList("a"), false);
			Path other = new CryptoPath(fileSystem, asList("b"), true);

			assertThat(pathWithoutParent.resolveSibling(other), is(other));
		}

		@Test
		public void testResolveSiblingDoesNotReturnOtherWhenOtherIsNotAbsoluteAndPathHasParent() {
			Path pathWithParent = new CryptoPath(fileSystem, asList("a", "b"), false);
			Path other = new CryptoPath(fileSystem, asList("c"), false);
			Path expected = new CryptoPath(fileSystem, asList("a", "c"), false);

			assertThat(pathWithParent.resolveSibling(other), is(expected));
		}

	}

	public class EqualsTest {

		@Test
		public void testPathFromOtherProviderIsNotEqual() {
			Path inTest = new CryptoPath(fileSystem, asList("a"), false);
			Path defaultProviderPath = Paths.get("a");

			assertThat(inTest, is(not(equalTo(defaultProviderPath))));
		}

		@Test
		public void testPathFromOtherFileSystemIsNotEqual() {
			Path inTest = path("a");
			Path other = cryptoPathFactory.getPath(mock(CryptoFileSystem.class), "a");

			assertThat(inTest, is(not(equalTo(other))));
		}

		@Test
		public void testAbsoluteAndRelativePathsAreNotEqual() {
			Path absolute = new CryptoPath(fileSystem, asList("a"), false);
			Path relative = new CryptoPath(fileSystem, asList("a"), true);

			assertThat(absolute, is(not(equalTo(relative))));
			assertThat(relative, is(not(equalTo(absolute))));
		}

		@Test
		public void testAbsolutePathsWithDifferentNamesAreNotEqual() {
			Path a = new CryptoPath(fileSystem, asList("a"), true);
			Path b = new CryptoPath(fileSystem, asList("b"), true);

			assertThat(a, is(not(equalTo(b))));
		}

		@Test
		public void testRelativePathsWithDifferentNamesAreNotEqual() {
			Path a = new CryptoPath(fileSystem, asList("a"), false);
			Path b = new CryptoPath(fileSystem, asList("b"), false);

			assertThat(a, is(not(equalTo(b))));
		}

		@Test
		public void testPathsWithDifferentLengthAreNotEqual() {
			Path a = new CryptoPath(fileSystem, asList("a/b"), false);
			Path b = new CryptoPath(fileSystem, asList("a"), false);

			assertThat(a, is(not(equalTo(b))));
			assertThat(b, is(not(equalTo(a))));
		}

		@Test
		public void testEqualPathsAreEqual() {
			Path a = new CryptoPath(fileSystem, asList("a"), false);
			Path b = new CryptoPath(fileSystem, asList("a"), false);

			assertThat(a, is(equalTo(b)));
			assertThat(b, is(equalTo(a)));
		}

	}

	public class CompareToTest {

		@Test
		public void testCompareToThrowsClassCastExceptionIfPathIsFromDifferentProvider() {
			Path inTest = new CryptoPath(fileSystem, asList("a"), true);
			Path defaultProviderPath = Paths.get("a");

			thrown.expect(ClassCastException.class);

			inTest.compareTo(defaultProviderPath);
		}

		@Test
		public void testAbsolutePathIsLessThanRelativePath() {
			Path absolute = new CryptoPath(fileSystem, asList("a"), true);
			Path relative = new CryptoPath(fileSystem, asList("a"), false);

			assertThat(absolute, is(lessThan(relative)));
		}

		@Test
		public void testRelativePathIsGreaterAbsolutePath() {
			Path absolute = new CryptoPath(fileSystem, asList("a"), true);
			Path relative = new CryptoPath(fileSystem, asList("a"), false);

			assertThat(relative, is(greaterThan(absolute)));
		}

		@Test
		public void testPathWithSmallerNameIsSmaller() {
			Path smaller = new CryptoPath(fileSystem, asList("a"), true);
			Path greater = new CryptoPath(fileSystem, asList("b"), true);

			assertThat(smaller, is(lessThan(greater)));
		}

		@Test
		public void testPathWithGreaterNameIsGreater() {
			Path smaller = new CryptoPath(fileSystem, asList("a"), true);
			Path greater = new CryptoPath(fileSystem, asList("b"), true);

			assertThat(greater, is(greaterThan(smaller)));
		}

		@Test
		public void testLongerPathIsGreater() {
			Path longer = new CryptoPath(fileSystem, asList("a/b"), true);
			Path shorter = new CryptoPath(fileSystem, asList("a"), true);

			assertThat(longer, is(greaterThan(shorter)));
		}

		@Test
		public void testShorterPathIsSmaller() {
			Path longer = new CryptoPath(fileSystem, asList("a/b"), true);
			Path shorter = new CryptoPath(fileSystem, asList("a"), true);

			assertThat(shorter, is(lessThan(longer)));
		}

		@Test
		public void testEqualPathsAreEqualAccordingToCompareTo() {
			Path a = new CryptoPath(fileSystem, asList("a/b"), true);
			Path b = new CryptoPath(fileSystem, asList("a/b"), true);

			assertThat(a, is(comparesEqualTo(b)));
		}

	}

	public class RelativizeTest {

		@Test
		public void testRelativizeWithIncompatiblePaths1() {
			Path relPath = path("a");
			Path absPath = path("/a");

			thrown.expect(IllegalArgumentException.class);
			relPath.relativize(absPath);
		}

		@Test
		public void testRelativizeWithIncompatiblePaths2() {
			Path relPath = path("a");
			Path absPath = path("/a");

			thrown.expect(IllegalArgumentException.class);
			absPath.relativize(relPath);
		}

		@Test
		public void testRelativizeWithIncompatiblePaths3() {
			Path path = path("/a");
			Path alienPath = FileSystems.getDefault().getPath("foo");

			thrown.expect(ProviderMismatchException.class);
			path.relativize(alienPath);
		}

		@Test
		public void testRelativizeWithEqualPath() {
			Path p1 = path("a/b");
			Path p2 = path("a").resolve("b");

			Path relativized = p1.relativize(p2);
			Assert.assertThat(relativized, is(equalTo(emptyPath)));
		}

		@Test
		public void testRelativizeWithUnrelatedPath() {
			Path p1 = path("a/b");
			Path p2 = path("c/d");
			// a/b .resolve( ../../c/d ) = c/d
			// thus: a/b .relativize ( c/d ) = ../../c/d

			Path relativized = p1.relativize(p2);
			Assert.assertEquals(path("../../c/d"), relativized);
		}

		@Test
		public void testRelativizeWithRelativeRelatedPath() {
			Path p1 = path("a/b");
			Path p2 = path("a/././c");
			Path p3 = path("a/b/c");

			Path relativized12 = p1.relativize(p2);
			Assert.assertEquals(path("../c"), relativized12);

			Path relativized13 = p1.relativize(p3);
			Assert.assertEquals(path("c"), relativized13);

			Path relativized32 = p3.relativize(p2);
			Assert.assertEquals(path("../../c"), relativized32);
		}

		@Test
		public void testRelativizeWithAbsoluteRelatedPath() {
			Path p1 = path("/a/b");
			Path p2 = path("/a/././c");
			Path p3 = path("/a/b/c");

			Path relativized12 = p1.relativize(p2);
			Assert.assertEquals(path("../c"), relativized12);

			Path relativized13 = p1.relativize(p3);
			Assert.assertEquals(path("c"), relativized13);

			Path relativized32 = p3.relativize(p2);
			Assert.assertEquals(path("../../c"), relativized32);
		}

	}

	public Path path(String first, String... more) {
		return cryptoPathFactory.getPath(fileSystem, first, more);
	}

}
