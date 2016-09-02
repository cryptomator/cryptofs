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
import static org.junit.Assert.assertThat;
import static org.mockito.Mockito.mock;

import java.io.IOException;
import java.net.URI;
import java.nio.file.FileSystems;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.ProviderMismatchException;
import java.nio.file.WatchEvent;
import java.nio.file.WatchService;
import java.nio.file.spi.FileSystemProvider;
import java.util.Arrays;
import java.util.Collections;

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
public class BasicPathTest {

	@Rule
	public final ExpectedException thrown = ExpectedException.none();

	private static final String FS_SCHEME = "MOCK";
	private BasicFileSystem fs;
	private BasicPath fsRoot;
	private BasicPath emptyPath;

	@Before
	public void setup() {
		FileSystemProvider fsProvider = Mockito.mock(FileSystemProvider.class);
		fs = Mockito.mock(BasicFileSystem.class);
		fsRoot = new BasicPath(fs, Collections.emptyList(), true);
		emptyPath = new BasicPath(fs, Collections.emptyList(), false);
		Mockito.when(fs.getPath(Mockito.anyString(), Mockito.anyVararg())).thenCallRealMethod();
		Mockito.when(fs.getSeparator()).thenCallRealMethod();
		Mockito.when(fs.getRootDirectory()).thenReturn(fsRoot);
		Mockito.when(fs.getEmptyPath()).thenReturn(emptyPath);
		Mockito.when(fs.provider()).thenReturn(fsProvider);
		Mockito.when(fs.toUri(Mockito.any())).thenCallRealMethod();
		Mockito.when(fsProvider.getScheme()).thenReturn(FS_SCHEME);
	}

	@Test
	public void testIsAbsolute() {
		Path p1 = fs.getPath("/foo/bar");
		Path p2 = fs.getPath("foo/bar");
		Assert.assertTrue(p1.isAbsolute());
		Assert.assertFalse(p2.isAbsolute());
	}

	@Test
	public void testStartsWith() {
		Path p1 = fs.getPath("/foo/bar");
		Path p2 = fs.getPath("/foo");
		Path p3 = fs.getPath("foo/bar");
		Path p4 = fs.getPath("foo");

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
		Path p1 = fs.getPath("/foo/bar");
		Path p2 = fs.getPath("bar");
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
		Path p1 = fs.getPath("/foo");
		Path p2 = fs.getPath("/foo/bar");
		Path p3 = fs.getPath("foo");

		Assert.assertEquals(p1, p2.getParent());
		Assert.assertEquals(fsRoot, p1.getParent());
		Assert.assertNull(emptyPath.getParent());
		Assert.assertNull(p3.getParent());
	}

	@Test
	public void testToString() {
		Path p1 = fs.getPath("/foo/bar");
		Path p2 = fs.getPath("foo/bar");
		Assert.assertEquals("/foo/bar", p1.toString());
		Assert.assertEquals("foo/bar", p2.toString());
	}

	@Test
	public void testNormalize() {
		Path p = fs.getPath("/../../foo/bar/.///../baz").normalize();
		Assert.assertEquals("/../../foo/baz", p.toString());
	}

	@Test
	public void testToUri() {
		Path p = fs.getPath("/foo/bar");
		URI uri = p.toUri();
		Assert.assertEquals(URI.create(FS_SCHEME + ":/foo/bar"), uri);
	}

	@Test
	public void testEquality() {
		Path p1 = fs.getPath("/foo");
		Assert.assertNotEquals(p1, null);
		Assert.assertNotEquals(p1, "string");

		Path p2 = fs.getPath("/foo");
		Assert.assertEquals(p1.hashCode(), p2.hashCode());
		Assert.assertEquals(p1, p2);

		Path p3 = fs.getPath("foo");
		Assert.assertNotEquals(p1, p3);

		Path p4 = p3.resolve("bar");
		Path p5 = fs.getPath("foo/bar");
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

		fsRoot.register(irrelevantWatcher, irrelevantWatchEvents, irrelevantModifiers);
	}

	@Test
	public void testRegisterWithTwoParamsThrowsUnsupportedOperationException() throws IOException {
		WatchService irrelevantWatcher = null;
		WatchEvent.Kind<?>[] irrelevantWatchEvents = null;

		thrown.expect(UnsupportedOperationException.class);

		fsRoot.register(irrelevantWatcher, irrelevantWatchEvents);
	}

	@Test
	public void testIterator() {
		Path p = fs.getPath("/foo/bar/baz");
		Assert.assertArrayEquals(Arrays.asList("foo", "bar", "baz").toArray(), Lists.newArrayList(p.iterator()).stream().map(Path::toString).toArray());
	}

	@Test
	public void testGetFileName() {
		Path p = fs.getPath("/foo/bar/baz");
		Path name = p.getFileName();
		Assert.assertEquals(fs.getPath("baz"), name);
		Assert.assertNull(emptyPath.getFileName());
	}

	@Test
	public void testGetRootForAbsolutePath() {
		BasicPath path = new BasicPath(fs, asList("a"), true);

		assertThat(path.getRoot(), is(fsRoot));
	}

	@Test
	public void testGetRootForNonAbsolutePath() {
		BasicPath path = new BasicPath(fs, asList("a"), false);

		assertThat(path.getRoot(), is(nullValue()));
	}

	@Test
	public void testToAbsolutePathReturnsThisIfAlreadyAbsolute() {
		Path inTest = new BasicPath(fs, asList("a", "b"), true);

		assertThat(inTest.toAbsolutePath(), is(sameInstance(inTest)));
	}

	@Test
	public void testToAbsolutePathReturnsAbsolutePathIfNotAlreadyAbsolute() {
		Path inTest = new BasicPath(fs, asList("a", "b"), false);
		Path absolutePath = new BasicPath(fs, asList("a", "b"), true);

		assertThat(inTest.toAbsolutePath(), is(absolutePath));
	}

	@Test
	public void testToRealPathReturnsThisIfAlreadyAbsolute() throws IOException {
		Path inTest = new BasicPath(fs, asList("a", "b"), true);

		assertThat(inTest.toRealPath(), is(sameInstance(inTest)));
	}

	@Test
	public void testToRealPathReturnsAbsolutePathIfNotAlreadyAbsolute() throws IOException {
		Path inTest = new BasicPath(fs, asList("a", "b"), false);
		Path absolutePath = new BasicPath(fs, asList("a", "b"), true);

		assertThat(inTest.toRealPath(), is(absolutePath));
	}

	@Test
	public void testToFileThrowsUnsupportedOperationException() {
		thrown.expect(UnsupportedOperationException.class);

		new BasicPath(fs, asList("a"), true).toFile();
	}

	@Test
	public void testGetFileSystemReturnsFileSystem() {
		Path inTest = new BasicPath(fs, asList("a"), false);

		assertThat(inTest.getFileSystem(), is(fs));
	}

	public class ResolveTest {

		@Test
		public void testResolve() {
			Path p1 = fs.getPath("/foo");
			Path p2 = p1.resolve("bar");
			Assert.assertEquals(fs.getPath("/foo/bar"), p2);

			Path p3 = fs.getPath("foo");
			Path p4 = p3.resolve("bar");
			Assert.assertEquals(fs.getPath("foo/bar"), p4);

			Path p5 = fs.getPath("/abs/path");
			Path p6 = p4.resolve(p5);
			Assert.assertEquals(p5, p6);
		}

		@Test
		public void testResolveSiblingReturnsOtherWhenPathHasNoParent() {
			Path pathWithoutParent = new BasicPath(fs, asList("a"), false);
			Path other = new BasicPath(fs, asList("b"), false);

			assertThat(pathWithoutParent.resolveSibling(other), is(other));
		}

		@Test
		public void testResolveSiblingReturnsOtherWhenOtherIsAbsolute() {
			Path pathWithParent = new BasicPath(fs, asList("a", "b"), true);
			Path other = new BasicPath(fs, asList("b"), true);

			assertThat(pathWithParent.resolveSibling(other), is(other));
		}

		@Test
		public void testResolveSiblingReturnsOtherWhenOtherIsAbsoluteAndPathHasNoParent() {
			Path pathWithoutParent = new BasicPath(fs, asList("a"), false);
			Path other = new BasicPath(fs, asList("b"), true);

			assertThat(pathWithoutParent.resolveSibling(other), is(other));
		}

		@Test
		public void testResolveSiblingDoesNotReturnOtherWhenOtherIsNotAbsoluteAndPathHasParent() {
			Path pathWithParent = new BasicPath(fs, asList("a", "b"), false);
			Path other = new BasicPath(fs, asList("c"), false);
			Path expected = new BasicPath(fs, asList("a", "c"), false);

			assertThat(pathWithParent.resolveSibling(other), is(expected));
		}

	}

	public class EqualsTest {

		@Test
		public void testPathFromOtherProviderIsNotEqual() {
			Path inTest = new BasicPath(fs, asList("a"), false);
			Path defaultProviderPath = Paths.get("a");

			assertThat(inTest, is(not(equalTo(defaultProviderPath))));
		}

		@Test
		public void testPathFromOtherFileSystemIsNotEqual() {
			Path inTest = new BasicPath(fs, asList("a"), false);
			Path other = new BasicPath(mock(BasicFileSystem.class), asList("a"), false);

			assertThat(inTest, is(not(equalTo(other))));
		}

		@Test
		public void testAbsoluteAndRelativePathsAreNotEqual() {
			Path absolute = new BasicPath(fs, asList("a"), false);
			Path relative = new BasicPath(fs, asList("a"), true);

			assertThat(absolute, is(not(equalTo(relative))));
			assertThat(relative, is(not(equalTo(absolute))));
		}

		@Test
		public void testAbsolutePathsWithDifferentNamesAreNotEqual() {
			Path a = new BasicPath(fs, asList("a"), true);
			Path b = new BasicPath(fs, asList("b"), true);

			assertThat(a, is(not(equalTo(b))));
		}

		@Test
		public void testRelativePathsWithDifferentNamesAreNotEqual() {
			Path a = new BasicPath(fs, asList("a"), false);
			Path b = new BasicPath(fs, asList("b"), false);

			assertThat(a, is(not(equalTo(b))));
		}

		@Test
		public void testPathsWithDifferentLengthAreNotEqual() {
			Path a = new BasicPath(fs, asList("a/b"), false);
			Path b = new BasicPath(fs, asList("a"), false);

			assertThat(a, is(not(equalTo(b))));
			assertThat(b, is(not(equalTo(a))));
		}

		@Test
		public void testEqualPathsAreEqual() {
			Path a = new BasicPath(fs, asList("a"), false);
			Path b = new BasicPath(fs, asList("a"), false);

			assertThat(a, is(equalTo(b)));
			assertThat(b, is(equalTo(a)));
		}

	}

	public class CompareToTest {

		@Test
		public void testCompareToThrowsClassCastExceptionIfPathIsFromDifferentProvider() {
			Path inTest = new BasicPath(fs, asList("a"), true);
			Path defaultProviderPath = Paths.get("a");

			thrown.expect(ClassCastException.class);

			inTest.compareTo(defaultProviderPath);
		}

		@Test
		public void testAbsolutePathIsLessThanRelativePath() {
			Path absolute = new BasicPath(fs, asList("a"), true);
			Path relative = new BasicPath(fs, asList("a"), false);

			assertThat(absolute, is(lessThan(relative)));
		}

		@Test
		public void testRelativePathIsGreaterAbsolutePath() {
			Path absolute = new BasicPath(fs, asList("a"), true);
			Path relative = new BasicPath(fs, asList("a"), false);

			assertThat(relative, is(greaterThan(absolute)));
		}

		@Test
		public void testPathWithSmallerNameIsSmaller() {
			Path smaller = new BasicPath(fs, asList("a"), true);
			Path greater = new BasicPath(fs, asList("b"), true);

			assertThat(smaller, is(lessThan(greater)));
		}

		@Test
		public void testPathWithGreaterNameIsGreater() {
			Path smaller = new BasicPath(fs, asList("a"), true);
			Path greater = new BasicPath(fs, asList("b"), true);

			assertThat(greater, is(greaterThan(smaller)));
		}

		@Test
		public void testLongerPathIsGreater() {
			Path longer = new BasicPath(fs, asList("a/b"), true);
			Path shorter = new BasicPath(fs, asList("a"), true);

			assertThat(longer, is(greaterThan(shorter)));
		}

		@Test
		public void testShorterPathIsSmaller() {
			Path longer = new BasicPath(fs, asList("a/b"), true);
			Path shorter = new BasicPath(fs, asList("a"), true);

			assertThat(shorter, is(lessThan(longer)));
		}

		@Test
		public void testEqualPathsAreEqualAccordingToCompareTo() {
			Path a = new BasicPath(fs, asList("a/b"), true);
			Path b = new BasicPath(fs, asList("a/b"), true);

			assertThat(a, is(comparesEqualTo(b)));
		}

	}

	public class RelativizeTest {

		@Test
		public void testRelativizeWithIncompatiblePaths1() {
			Path relPath = fs.getPath("a");
			Path absPath = fs.getPath("/a");

			thrown.expect(IllegalArgumentException.class);
			relPath.relativize(absPath);
		}

		@Test
		public void testRelativizeWithIncompatiblePaths2() {
			Path relPath = fs.getPath("a");
			Path absPath = fs.getPath("/a");

			thrown.expect(IllegalArgumentException.class);
			absPath.relativize(relPath);
		}

		@Test
		public void testRelativizeWithIncompatiblePaths3() {
			Path path = fs.getPath("/a");
			Path alienPath = FileSystems.getDefault().getPath("foo");

			thrown.expect(ProviderMismatchException.class);
			path.relativize(alienPath);
		}

		@Test
		public void testRelativizeWithEqualPath() {
			Path p1 = fs.getPath("a/b");
			Path p2 = fs.getPath("a").resolve("b");

			Path relativized = p1.relativize(p2);
			Assert.assertThat(relativized, is(equalTo(emptyPath)));
		}

		@Test
		public void testRelativizeWithUnrelatedPath() {
			Path p1 = fs.getPath("a/b");
			Path p2 = fs.getPath("c/d");
			// a/b .resolve( ../../c/d ) = c/d
			// thus: a/b .relativize ( c/d ) = ../../c/d

			Path relativized = p1.relativize(p2);
			Assert.assertEquals(fs.getPath("../../c/d"), relativized);
		}

		@Test
		public void testRelativizeWithRelativeRelatedPath() {
			Path p1 = fs.getPath("a/b");
			Path p2 = fs.getPath("a/././c");
			Path p3 = fs.getPath("a/b/c");

			Path relativized12 = p1.relativize(p2);
			Assert.assertEquals(fs.getPath("../c"), relativized12);

			Path relativized13 = p1.relativize(p3);
			Assert.assertEquals(fs.getPath("c"), relativized13);

			Path relativized32 = p3.relativize(p2);
			Assert.assertEquals(fs.getPath("../../c"), relativized32);
		}

		@Test
		public void testRelativizeWithAbsoluteRelatedPath() {
			Path p1 = fs.getPath("/a/b");
			Path p2 = fs.getPath("/a/././c");
			Path p3 = fs.getPath("/a/b/c");

			Path relativized12 = p1.relativize(p2);
			Assert.assertEquals(fs.getPath("../c"), relativized12);

			Path relativized13 = p1.relativize(p3);
			Assert.assertEquals(fs.getPath("c"), relativized13);

			Path relativized32 = p3.relativize(p2);
			Assert.assertEquals(fs.getPath("../../c"), relativized32);
		}

	}

}
