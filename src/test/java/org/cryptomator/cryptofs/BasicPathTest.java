/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptofs;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.is;

import java.io.IOException;
import java.net.URI;
import java.nio.file.FileSystems;
import java.nio.file.Path;
import java.nio.file.ProviderMismatchException;
import java.nio.file.StandardWatchEventKinds;
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
	private FileSystemProvider fsProvider;
	private BasicFileSystem fs;
	private BasicPath fsRoot;
	private BasicPath emptyPath;

	@Before
	public void setup() {
		fsProvider = Mockito.mock(FileSystemProvider.class);
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
		Assert.assertTrue(p1.startsWith(p1));
		Assert.assertTrue(p1.startsWith(p2));
		Assert.assertTrue(p1.startsWith("/foo"));
		Assert.assertFalse(p1.startsWith("/fo"));
		Path p3 = fs.getPath("foo/bar");
		Path p4 = fs.getPath("foo");
		Assert.assertFalse(p1.startsWith(p3));
		Assert.assertFalse(p1.startsWith(p4));
		Assert.assertTrue(p3.startsWith("foo"));
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

		Assert.assertEquals(p1, p2.getParent());
		Assert.assertEquals(fsRoot, p1.getParent());
		Assert.assertEquals(fsRoot, fsRoot.getParent());
		Assert.assertNull(emptyPath.getParent());
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
	public void testRegister() throws IOException {
		thrown.expect(UnsupportedOperationException.class);
		fsRoot.register(Mockito.mock(WatchService.class), new WatchEvent.Kind[] {StandardWatchEventKinds.ENTRY_CREATE});
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
		public void testResolveSibling() {
			Path p1 = fs.getPath("foo/bar");
			Path p2 = p1.resolveSibling("baz");
			Assert.assertEquals(fs.getPath("foo/baz"), p2);

			Path p3 = fs.getPath("/foo/bar");
			Path p4 = p3.resolveSibling("baz");
			Assert.assertEquals(fs.getPath("/foo/baz"), p4);

			Path p5 = fs.getPath("/abs/path");
			Path p6 = p4.resolveSibling(p5);
			Assert.assertEquals(p5, p6);
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
