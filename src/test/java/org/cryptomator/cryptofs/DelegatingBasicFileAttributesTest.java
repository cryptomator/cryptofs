/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptofs;

import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.FileTime;
import java.time.Instant;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;

public class DelegatingBasicFileAttributesTest {

	private BasicFileAttributes delegateAttr;
	private TestDelegatingBasicFileAttributes delegatingAttr;

	@Before
	public void setup() {
		delegateAttr = Mockito.mock(BasicFileAttributes.class);
		delegatingAttr = new TestDelegatingBasicFileAttributes(delegateAttr);
	}

	@Test
	public void testLastModifiedTime() {
		Mockito.when(delegateAttr.lastModifiedTime()).thenReturn(FileTime.from(Instant.now()));
		Assert.assertEquals(delegateAttr.lastModifiedTime(), delegatingAttr.lastModifiedTime());
	}

	@Test
	public void testLastAccessTime() {
		Mockito.when(delegateAttr.lastAccessTime()).thenReturn(FileTime.from(Instant.now()));
		Assert.assertEquals(delegateAttr.lastAccessTime(), delegatingAttr.lastAccessTime());
	}

	@Test
	public void testCreationTime() {
		Mockito.when(delegateAttr.creationTime()).thenReturn(FileTime.from(Instant.now()));
		Assert.assertEquals(delegateAttr.creationTime(), delegatingAttr.creationTime());
	}

	@Test
	public void testIsRegularFile() {
		Mockito.when(delegateAttr.isRegularFile()).thenReturn(true);
		Assert.assertTrue(delegatingAttr.isRegularFile());
	}

	@Test
	public void testIsDirectory() {
		Mockito.when(delegateAttr.isDirectory()).thenReturn(true);
		Assert.assertTrue(delegatingAttr.isDirectory());
	}

	@Test
	public void testIsSymbolicLink() {
		Mockito.when(delegateAttr.isSymbolicLink()).thenReturn(true);
		Assert.assertTrue(delegatingAttr.isSymbolicLink());
	}

	@Test
	public void testIsOther() {
		Mockito.when(delegateAttr.isOther()).thenReturn(true);
		Assert.assertTrue(delegatingAttr.isOther());
	}

	@Test
	public void testSize() {
		Mockito.when(delegateAttr.size()).thenReturn(1337l);
		Assert.assertEquals(delegateAttr.size(), delegatingAttr.size());
	}

	@Test
	public void testFileKey() {
		Mockito.when(delegateAttr.fileKey()).thenReturn(new Object());
		Assert.assertEquals(delegateAttr.fileKey(), delegatingAttr.fileKey());
	}

	private static class TestDelegatingBasicFileAttributes implements DelegatingBasicFileAttributes {
		private final BasicFileAttributes delegate;

		public TestDelegatingBasicFileAttributes(BasicFileAttributes delegate) {
			this.delegate = delegate;
		}

		@Override
		public BasicFileAttributes getDelegate() {
			return delegate;
		}
	}

}
