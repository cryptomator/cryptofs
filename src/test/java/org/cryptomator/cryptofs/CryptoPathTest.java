/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptofs;

import com.google.common.collect.Lists;
import org.hamcrest.MatcherAssert;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.file.FileSystems;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.ProviderMismatchException;
import java.nio.file.WatchEvent;
import java.nio.file.WatchService;
import java.util.Arrays;

import static java.util.Arrays.asList;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.Matchers.comparesEqualTo;
import static org.hamcrest.Matchers.greaterThan;
import static org.hamcrest.Matchers.lessThan;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyZeroInteractions;
import static org.mockito.Mockito.when;

public class CryptoPathTest {

	private CryptoFileSystemImpl fileSystem;

	private final Symlinks symlinks = Mockito.mock(Symlinks.class);
	private final CryptoPathFactory cryptoPathFactory = new CryptoPathFactory(symlinks);

	private CryptoPath rootPath;
	private CryptoPath emptyPath;

	@BeforeEach
	public void setup() {
		fileSystem = Mockito.mock(CryptoFileSystemImpl.class);
		rootPath = cryptoPathFactory.rootFor(fileSystem);
		emptyPath = cryptoPathFactory.emptyFor(fileSystem);
		when(fileSystem.getPath(any(String.class))).thenAnswer(invocation -> {
			String first = invocation.getArgument(0);
			return path(first);
		});

		when(fileSystem.getRootPath()).thenReturn(rootPath);
		when(fileSystem.getEmptyPath()).thenReturn(emptyPath);
	}

	@Test
	public void testIsAbsolute() {
		Path p1 = path("/foo/bar");
		Path p2 = path("foo/bar");
		Assertions.assertTrue(p1.isAbsolute());
		Assertions.assertFalse(p2.isAbsolute());
	}

	@Test
	public void testStartsWith() {
		Path p1 = path("/foo/bar");
		Path p2 = path("/foo");
		Path p3 = path("foo/bar");
		Path p4 = path("foo");

		Assertions.assertTrue(p1.startsWith(p1));
		Assertions.assertTrue(p1.startsWith(p2));
		Assertions.assertTrue(p1.startsWith("/foo"));
		Assertions.assertFalse(p1.startsWith("/fo"));
		Assertions.assertFalse(p2.startsWith(p1));
		Assertions.assertFalse(p1.startsWith(p3));
		Assertions.assertFalse(p1.startsWith(p4));
		Assertions.assertTrue(p3.startsWith("foo"));
		Assertions.assertTrue(p3.startsWith(p4));
		Assertions.assertFalse(p4.startsWith(p3));
	}

	@Test
	public void testEndsWith() {
		Path p1 = path("/foo/bar");
		Path p2 = path("bar");
		Assertions.assertTrue(p1.endsWith(p1));
		Assertions.assertTrue(p1.endsWith(p2));
		Assertions.assertTrue(p1.endsWith("bar"));
		Assertions.assertTrue(p1.endsWith("foo/bar"));
		Assertions.assertTrue(p1.endsWith("/foo/bar"));
		Assertions.assertFalse(p1.endsWith("ba"));
		Assertions.assertFalse(p1.endsWith("/foo/bar/baz"));
	}

	@Test
	public void testGetParent() {
		Path p1 = path("/foo");
		Path p2 = path("/foo/bar");
		Path p3 = path("foo");
		Path p4 = path("/");

		Assertions.assertEquals(p1, p2.getParent());
		Assertions.assertEquals(rootPath, p1.getParent());
		Assertions.assertNull(emptyPath.getParent());
		Assertions.assertNull(p3.getParent());
		Assertions.assertNull(p4.getParent());
	}

	@Test
	public void testToString() {
		Path p1 = path("/foo/bar");
		Path p2 = path("foo/bar");
		Assertions.assertEquals("/foo/bar", p1.toString());
		Assertions.assertEquals("foo/bar", p2.toString());
	}

	@Test
	public void testNormalize() {
		Path p = path("/../../foo/bar/.///../baz").normalize();
		Assertions.assertEquals("/../../foo/baz", p.toString());
	}

	@Test
	public void testToUri() throws URISyntaxException {
		Path pathToVault = mock(Path.class);
		when(pathToVault.toUri()).thenReturn(new URI("http://cryptomator.org/"));
		when(fileSystem.getPathToVault()).thenReturn(pathToVault);

		URI uri = path("/foo/bar").toUri();

		Assertions.assertEquals(new URI("cryptomator", "http://cryptomator.org/", "/foo/bar", null, null), uri);
	}

	@Test
	public void testEquality() {
		Path p1 = path("/foo");
		Assertions.assertNotEquals(p1, null);
		Assertions.assertNotEquals(p1, "string");

		Path p2 = path("/foo");
		Assertions.assertEquals(p1.hashCode(), p2.hashCode());
		Assertions.assertEquals(p1, p2);

		Path p3 = path("foo");
		Assertions.assertNotEquals(p1, p3);

		Path p4 = p3.resolve("bar");
		Path p5 = path("foo/bar");
		Assertions.assertEquals(p4.hashCode(), p5.hashCode());
		Assertions.assertEquals(p4, p5);

		Path p6 = p1.resolve("bar");
		Path p7 = p1.resolveSibling("foo/bar");
		Assertions.assertEquals(p6.hashCode(), p7.hashCode());
		Assertions.assertEquals(p6, p7);
	}

	@Test
	public void testRegisterWithThreeParamsThrowsUnsupportedOperationException() throws IOException {
		WatchService irrelevantWatcher = null;
		WatchEvent.Kind<?>[] irrelevantWatchEvents = null;
		WatchEvent.Modifier[] irrelevantModifiers = null;

		Assertions.assertThrows(UnsupportedOperationException.class, () -> {
			rootPath.register(irrelevantWatcher, irrelevantWatchEvents, irrelevantModifiers);
		});
	}

	@Test
	public void testRegisterWithTwoParamsThrowsUnsupportedOperationException() throws IOException {
		WatchService irrelevantWatcher = null;
		WatchEvent.Kind<?>[] irrelevantWatchEvents = null;

		Assertions.assertThrows(UnsupportedOperationException.class, () -> {
			rootPath.register(irrelevantWatcher, irrelevantWatchEvents);
		});
	}

	@Test
	public void testIterator() {
		Path p = path("/foo/bar/baz");
		Assertions.assertArrayEquals(Arrays.asList("foo", "bar", "baz").toArray(), Lists.newArrayList(p.iterator()).stream().map(Path::toString).toArray());
	}

	@Test
	public void testGetFileName() {
		Path p = path("/foo/bar/baz");
		Path name = p.getFileName();
		Assertions.assertEquals(path("baz"), name);
		Assertions.assertNull(emptyPath.getFileName());
	}

	@Test
	public void testGetRootForAbsolutePath() {
		CryptoPath path = new CryptoPath(fileSystem, symlinks, asList("a"), true);

		Assertions.assertEquals(rootPath, path.getRoot());
	}

	@Test
	public void testGetRootForNonAbsolutePath() {
		CryptoPath path = new CryptoPath(fileSystem, symlinks, asList("a"), false);

		Assertions.assertNull(path.getRoot());
	}

	@Test
	public void testToAbsolutePathReturnsThisIfAlreadyAbsolute() {
		Path inTest = new CryptoPath(fileSystem, symlinks, asList("a", "b"), true);

		Assertions.assertSame(inTest, inTest.toAbsolutePath());
	}

	@Test
	public void testToAbsolutePathReturnsAbsolutePathIfNotAlreadyAbsolute() {
		Path inTest = new CryptoPath(fileSystem, symlinks, asList("a", "b"), false);
		Path absolutePath = new CryptoPath(fileSystem, symlinks, asList("a", "b"), true);

		Assertions.assertEquals(absolutePath, inTest.toAbsolutePath());
	}

	@Test
	public void testToRealPathReturnsNormalizedAndAbsolutePath() throws IOException {
		when(symlinks.resolveRecursively(Mockito.any())).thenAnswer(invocation -> invocation.getArgument(0));

		Path inTest = new CryptoPath(fileSystem, symlinks, asList("a", ".", "b", "c", ".."), false);
		Path normalizedAndAbsolute = new CryptoPath(fileSystem, symlinks, asList("a", "b"), true);

		Assertions.assertEquals(normalizedAndAbsolute, inTest.toRealPath());
	}

	@Test
	public void testToRealPathResolvesSymlinks() throws IOException {
		CryptoPath ab = new CryptoPath(fileSystem, symlinks, asList("a", "b"), true);
		CryptoPath f = new CryptoPath(fileSystem, symlinks, asList("f"), true);
		CryptoPath fcde = new CryptoPath(fileSystem, symlinks, asList("f", "c", "d", "e"), true);
		CryptoPath fcg = new CryptoPath(fileSystem, symlinks, asList("f", "c", "g"), true);
		when(symlinks.resolveRecursively(any())).thenAnswer(invocation -> {
			CryptoPath p = invocation.getArgument(0);
			if (p.equals(ab)) {
				return f;
			} else if (p.equals(fcde)) {
				return fcg;
			} else {
				return p;
			}
		});

		Path inTest = new CryptoPath(fileSystem, symlinks, asList("a", ".", "b", "c", "d", "e"), true);
		Path normalizedAndAbsolute = new CryptoPath(fileSystem, symlinks, asList("f", "c", "g"), true);

		Assertions.assertEquals(normalizedAndAbsolute, inTest.toRealPath());
	}

	@Test
	public void testToRealPathDoesNotResolveSymlinksWhenNotFollowingLinks() throws IOException {
		Path inTest = new CryptoPath(fileSystem, symlinks, asList("a", ".", "b", "c", ".."), true);
		Path normalizedAndAbsolute = new CryptoPath(fileSystem, symlinks, asList("a", "b"), true);

		Assertions.assertEquals(normalizedAndAbsolute, inTest.toRealPath(LinkOption.NOFOLLOW_LINKS));
		verifyZeroInteractions(symlinks);
	}

	@Test
	public void testToFileThrowsUnsupportedOperationException() {
		Path inTest = new CryptoPath(fileSystem, symlinks, asList("a"), true);

		Assertions.assertThrows(UnsupportedOperationException.class, () -> {
			inTest.toFile();
		});
	}

	@Test
	public void testGetFileSystemReturnsFileSystem() {
		Path inTest = new CryptoPath(fileSystem, symlinks, asList("a"), false);

		Assertions.assertSame(fileSystem, inTest.getFileSystem());
	}

	@Nested
	public class ResolveTest {

		@Test
		public void testResolve() {
			Path p1 = path("/foo");
			Path p2 = p1.resolve("bar");
			Assertions.assertEquals(path("/foo/bar"), p2);

			Path p3 = path("foo");
			Path p4 = p3.resolve("bar");
			Assertions.assertEquals(path("foo/bar"), p4);

			Path p5 = path("/abs/path");
			Path p6 = p4.resolve(p5);
			Assertions.assertEquals(p5, p6);
		}

		@Test
		public void testResolveSiblingReturnsOtherWhenPathHasNoParent() {
			Path pathWithoutParent = new CryptoPath(fileSystem, symlinks, asList("a"), false);
			Path other = new CryptoPath(fileSystem, symlinks, asList("b"), false);

			Assertions.assertEquals(other, pathWithoutParent.resolveSibling(other));
		}

		@Test
		public void testResolveSiblingReturnsOtherWhenOtherIsAbsolute() {
			Path pathWithParent = new CryptoPath(fileSystem, symlinks, asList("a", "b"), true);
			Path other = new CryptoPath(fileSystem, symlinks, asList("b"), true);

			Assertions.assertEquals(other, pathWithParent.resolveSibling(other));
		}

		@Test
		public void testResolveSiblingReturnsOtherWhenOtherIsAbsoluteAndPathHasNoParent() {
			Path pathWithoutParent = new CryptoPath(fileSystem, symlinks, asList("a"), false);
			Path other = new CryptoPath(fileSystem, symlinks, asList("b"), true);

			Assertions.assertEquals(other, pathWithoutParent.resolveSibling(other));
		}

		@Test
		public void testResolveSiblingDoesNotReturnOtherWhenOtherIsNotAbsoluteAndPathHasParent() {
			Path pathWithParent = new CryptoPath(fileSystem, symlinks, asList("a", "b"), false);
			Path other = new CryptoPath(fileSystem, symlinks, asList("c"), false);
			Path expected = new CryptoPath(fileSystem, symlinks, asList("a", "c"), false);

			Assertions.assertEquals(expected, pathWithParent.resolveSibling(other));
		}

	}

	@Nested
	public class EqualsTest {

		@Test
		public void testPathFromOtherProviderIsNotEqual() {
			Path inTest = new CryptoPath(fileSystem, symlinks, asList("a"), false);
			Path defaultProviderPath = Paths.get("a");

			Assertions.assertNotEquals(defaultProviderPath, inTest);
		}

		@Test
		public void testPathFromOtherFileSystemIsNotEqual() {
			Path inTest = path("a");
			Path other = cryptoPathFactory.getPath(mock(CryptoFileSystemImpl.class), "a");

			Assertions.assertNotEquals(other, inTest);
		}

		@Test
		public void testAbsoluteAndRelativePathsAreNotEqual() {
			Path absolute = new CryptoPath(fileSystem, symlinks, asList("a"), false);
			Path relative = new CryptoPath(fileSystem, symlinks, asList("a"), true);

			Assertions.assertNotEquals(relative, absolute);
			Assertions.assertNotEquals(absolute, relative);
		}

		@Test
		public void testAbsolutePathsWithDifferentNamesAreNotEqual() {
			Path a = new CryptoPath(fileSystem, symlinks, asList("a"), true);
			Path b = new CryptoPath(fileSystem, symlinks, asList("b"), true);

			Assertions.assertNotEquals(b, a);
		}

		@Test
		public void testRelativePathsWithDifferentNamesAreNotEqual() {
			Path a = new CryptoPath(fileSystem, symlinks, asList("a"), false);
			Path b = new CryptoPath(fileSystem, symlinks, asList("b"), false);

			Assertions.assertNotEquals(b, a);
		}

		@Test
		public void testPathsWithDifferentLengthAreNotEqual() {
			Path a = new CryptoPath(fileSystem, symlinks, asList("a/b"), false);
			Path b = new CryptoPath(fileSystem, symlinks, asList("a"), false);

			Assertions.assertNotEquals(a, b);
			Assertions.assertNotEquals(b, a);
		}

		@Test
		public void testEqualPathsAreEqual() {
			Path a = new CryptoPath(fileSystem, symlinks, asList("a"), false);
			Path b = new CryptoPath(fileSystem, symlinks, asList("a"), false);

			Assertions.assertEquals(a, b);
			Assertions.assertEquals(b, a);
		}

	}

	@Nested
	public class CompareToTest {

		@Test
		public void testCompareToThrowsClassCastExceptionIfPathIsFromDifferentProvider() {
			Path inTest = new CryptoPath(fileSystem, symlinks, asList("a"), true);
			Path defaultProviderPath = Paths.get("a");

			Assertions.assertThrows(ClassCastException.class, () -> {
				inTest.compareTo(defaultProviderPath);
			});
		}

		@Test
		public void testAbsolutePathIsLessThanRelativePath() {
			Path absolute = new CryptoPath(fileSystem, symlinks, asList("a"), true);
			Path relative = new CryptoPath(fileSystem, symlinks, asList("a"), false);

			MatcherAssert.assertThat(absolute, is(lessThan(relative)));
		}

		@Test
		public void testRelativePathIsGreaterAbsolutePath() {
			Path absolute = new CryptoPath(fileSystem, symlinks, asList("a"), true);
			Path relative = new CryptoPath(fileSystem, symlinks, asList("a"), false);

			MatcherAssert.assertThat(relative, is(greaterThan(absolute)));
		}

		@Test
		public void testPathWithSmallerNameIsSmaller() {
			Path smaller = new CryptoPath(fileSystem, symlinks, asList("a"), true);
			Path greater = new CryptoPath(fileSystem, symlinks, asList("b"), true);

			MatcherAssert.assertThat(smaller, is(lessThan(greater)));
		}

		@Test
		public void testPathWithGreaterNameIsGreater() {
			Path smaller = new CryptoPath(fileSystem, symlinks, asList("a"), true);
			Path greater = new CryptoPath(fileSystem, symlinks, asList("b"), true);

			MatcherAssert.assertThat(greater, is(greaterThan(smaller)));
		}

		@Test
		public void testLongerPathIsGreater() {
			Path longer = new CryptoPath(fileSystem, symlinks, asList("a/b"), true);
			Path shorter = new CryptoPath(fileSystem, symlinks, asList("a"), true);

			MatcherAssert.assertThat(longer, is(greaterThan(shorter)));
		}

		@Test
		public void testShorterPathIsSmaller() {
			Path longer = new CryptoPath(fileSystem, symlinks, asList("a/b"), true);
			Path shorter = new CryptoPath(fileSystem, symlinks, asList("a"), true);

			MatcherAssert.assertThat(shorter, is(lessThan(longer)));
		}

		@Test
		public void testEqualPathsAreEqualAccordingToCompareTo() {
			Path a = new CryptoPath(fileSystem, symlinks, asList("a/b"), true);
			Path b = new CryptoPath(fileSystem, symlinks, asList("a/b"), true);

			MatcherAssert.assertThat(a, is(comparesEqualTo(b)));
		}

	}

	@Nested
	public class RelativizeTest {

		@Test
		public void testRelativizeWithIncompatiblePaths1() {
			Path relPath = path("a");
			Path absPath = path("/a");

			Assertions.assertThrows(IllegalArgumentException.class, () -> {
				relPath.relativize(absPath);
			});
		}

		@Test
		public void testRelativizeWithIncompatiblePaths2() {
			Path relPath = path("a");
			Path absPath = path("/a");

			Assertions.assertThrows(IllegalArgumentException.class, () -> {
				absPath.relativize(relPath);
			});
		}

		@Test
		public void testRelativizeWithIncompatiblePaths3() {
			Path path = path("/a");
			Path alienPath = FileSystems.getDefault().getPath("foo");

			Assertions.assertThrows(ProviderMismatchException.class, () -> {
				path.relativize(alienPath);
			});
		}

		@Test
		public void testRelativizeWithEqualPath() {
			Path p1 = path("a/b");
			Path p2 = path("a").resolve("b");

			Path relativized = p1.relativize(p2);
			Assertions.assertEquals(emptyPath, relativized);
		}

		@Test
		public void testRelativizeWithUnrelatedPath() {
			Path p1 = path("a/b");
			Path p2 = path("c/d");
			// a/b .resolve( ../../c/d ) = c/d
			// thus: a/b .relativize ( c/d ) = ../../c/d

			Path relativized = p1.relativize(p2);
			Assertions.assertEquals(path("../../c/d"), relativized);
		}

		@Test
		public void testRelativizeWithRelativeRelatedPath() {
			Path p1 = path("a/b");
			Path p2 = path("a/././c");
			Path p3 = path("a/b/c");

			Path relativized12 = p1.relativize(p2);
			Assertions.assertEquals(path("../c"), relativized12);

			Path relativized13 = p1.relativize(p3);
			Assertions.assertEquals(path("c"), relativized13);

			Path relativized32 = p3.relativize(p2);
			Assertions.assertEquals(path("../../c"), relativized32);
		}

		@Test
		public void testRelativizeWithAbsoluteRelatedPath() {
			Path p1 = path("/a/b");
			Path p2 = path("/a/././c");
			Path p3 = path("/a/b/c");

			Path relativized12 = p1.relativize(p2);
			Assertions.assertEquals(path("../c"), relativized12);

			Path relativized13 = p1.relativize(p3);
			Assertions.assertEquals(path("c"), relativized13);

			Path relativized32 = p3.relativize(p2);
			Assertions.assertEquals(path("../../c"), relativized32);
		}

	}

	public Path path(String first, String... more) {
		return cryptoPathFactory.getPath(fileSystem, first, more);
	}

}
