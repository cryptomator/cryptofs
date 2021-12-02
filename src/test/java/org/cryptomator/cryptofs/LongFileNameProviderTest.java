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
import java.nio.file.Paths;
import java.nio.file.ReadOnlyFileSystemException;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.Collections;
import java.util.Optional;
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
	public void testIsDeflated() {
		Assertions.assertTrue(new LongFileNameProvider(readonlyFlag).isDeflated("foo.c9s"));
		Assertions.assertFalse(new LongFileNameProvider(readonlyFlag).isDeflated("foo.txt"));
	}

	@Test
	public void testDeflateAndInflate(@TempDir Path tmpPath) throws IOException {
		String orig = "longName";
		LongFileNameProvider prov1 = new LongFileNameProvider(readonlyFlag);
		LongFileNameProvider.DeflatedFileName deflated = prov1.deflate(tmpPath.resolve(orig));
		String inflated1 = prov1.inflate(deflated.c9sPath);
		Assertions.assertEquals(orig, inflated1);

		Assertions.assertEquals(0, countFiles(tmpPath));
		deflated.persist();
		Assertions.assertEquals(1, countFiles(tmpPath));

		LongFileNameProvider prov2 = new LongFileNameProvider(readonlyFlag);
		String inflated2 = prov2.inflate(deflated.c9sPath);
		Assertions.assertEquals(orig, inflated2);
	}

	@Test
	public void testInflateNonExisting() {
		LongFileNameProvider prov = new LongFileNameProvider(readonlyFlag);

		Assertions.assertThrows(NoSuchFileException.class, () -> {
			prov.inflate(Paths.get("/does/not/exist"));
		});
	}

	@Test
	public void testDeflateMultipleTimes(@TempDir Path tmpPath) {
		LongFileNameProvider prov = new LongFileNameProvider(readonlyFlag);
		Path canonicalFileName = tmpPath.resolve("longName");

		Assertions.assertDoesNotThrow(() -> {
			prov.deflate(canonicalFileName);
			prov.deflate(canonicalFileName);
			prov.deflate(canonicalFileName);
			prov.deflate(canonicalFileName);
		});
	}

	@Test
	public void testPerstistCachedFailsOnReadOnlyFileSystems(@TempDir Path tmpPath) {
		LongFileNameProvider prov = new LongFileNameProvider(readonlyFlag);

		String orig = "longName";
		Path canonicalFileName = tmpPath.resolve(orig);
		LongFileNameProvider.DeflatedFileName deflated = prov.deflate(canonicalFileName);

		Mockito.doThrow(new ReadOnlyFileSystemException()).when(readonlyFlag).assertWritable();
		Assertions.assertThrows(ReadOnlyFileSystemException.class, () -> {
			deflated.persist();
		});
	}

}
