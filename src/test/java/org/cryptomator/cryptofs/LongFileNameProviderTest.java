/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptofs;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.Mockito;

import java.io.IOException;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.ReadOnlyFileSystemException;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.Collections;
import java.util.concurrent.atomic.AtomicInteger;

public class LongFileNameProviderTest {

	private final ReadonlyFlag readonlyFlag = Mockito.mock(ReadonlyFlag.class);

	private int countFiles(Path dir) throws IOException {
		AtomicInteger count = new AtomicInteger();
		Files.walkFileTree(dir, Collections.emptySet(), 2, new SimpleFileVisitor<Path>() {

			@Override
			public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) {
				count.incrementAndGet();
				return FileVisitResult.CONTINUE;
			}

		});
		return count.get();
	}

	@Test
	public void testIsDeflated(@TempDir Path tmpPath) {
		Path aPath = tmpPath.resolve("foo");
		Assertions.assertTrue(new LongFileNameProvider(aPath, readonlyFlag).isDeflated("foo.lng"));
		Assertions.assertFalse(new LongFileNameProvider(aPath, readonlyFlag).isDeflated("foo.txt"));
	}

	@Test
	public void testDeflateAndInflate(@TempDir Path tmpPath) throws IOException {
		String orig = "longName";
		LongFileNameProvider prov1 = new LongFileNameProvider(tmpPath, readonlyFlag);
		String deflated = prov1.deflate(orig);
		String inflated1 = prov1.inflate(deflated);
		Assertions.assertEquals(orig, inflated1);

		Assertions.assertEquals(0, countFiles(tmpPath));
		prov1.persistCached(deflated);
		Assertions.assertEquals(1, countFiles(tmpPath));

		LongFileNameProvider prov2 = new LongFileNameProvider(tmpPath, readonlyFlag);
		String inflated2 = prov2.inflate(deflated);
		Assertions.assertEquals(orig, inflated2);
	}

	@Test
	public void testInflateNonExisting(@TempDir Path tmpPath) {
		LongFileNameProvider prov = new LongFileNameProvider(tmpPath, readonlyFlag);

		Assertions.assertThrows(NoSuchFileException.class, () -> {
			prov.inflate("doesNotExist");
		});
	}

	@Test
	public void testDeflateMultipleTimes(@TempDir Path tmpPath) {
		LongFileNameProvider prov = new LongFileNameProvider(tmpPath, readonlyFlag);
		String orig = "longName";
		prov.deflate(orig);
		prov.deflate(orig);
		prov.deflate(orig);
		prov.deflate(orig);
	}

	@Test
	public void testPerstistCachedFailsOnReadOnlyFileSystems(@TempDir Path tmpPath) {
		LongFileNameProvider prov = new LongFileNameProvider(tmpPath, readonlyFlag);

		Mockito.doThrow(new ReadOnlyFileSystemException()).when(readonlyFlag).assertWritable();
		Assertions.assertThrows(ReadOnlyFileSystemException.class, () -> {
			prov.persistCached("whatever");
		});
	}

}
