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

import java.io.IOException;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.Collections;
import java.util.concurrent.atomic.AtomicInteger;

public class LongFileNameProviderTest {

	private int countFiles(Path dir) throws IOException {
		AtomicInteger count = new AtomicInteger();
		Files.walkFileTree(dir, Collections.emptySet(), 2, new SimpleFileVisitor<Path>() {

			@Override
			public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) throws IOException {
				count.incrementAndGet();
				return FileVisitResult.CONTINUE;
			}

		});
		return count.get();
	}

	@Test
	public void testIsDeflated(@TempDir Path tmpPath) throws IOException {
		Path aPath = tmpPath.resolve("foo");
		Assertions.assertTrue(new LongFileNameProvider(aPath).isDeflated("foo.lng"));
		Assertions.assertFalse(new LongFileNameProvider(aPath).isDeflated("foo.txt"));
	}

	@Test
	public void testDeflateAndInflate(@TempDir Path tmpPath) throws IOException {
		String orig = "longName";
		Assertions.assertEquals(0, countFiles(tmpPath));
		LongFileNameProvider prov1 = new LongFileNameProvider(tmpPath);
		String deflated = prov1.deflate(orig);
		Assertions.assertEquals(1, countFiles(tmpPath));
		LongFileNameProvider prov2 = new LongFileNameProvider(tmpPath);
		String inflated = prov2.inflate(deflated);
		Assertions.assertEquals(orig, inflated);
	}

	@Test
	public void testInflateNonExisting(@TempDir Path tmpPath) throws IOException {
		LongFileNameProvider prov = new LongFileNameProvider(tmpPath);

		Assertions.assertThrows(IOException.class, () -> {
			prov.inflate("doesNotExist");
		});
	}

	@Test
	public void testDeflateMultipleTimes(@TempDir Path tmpPath) throws IOException {
		LongFileNameProvider prov = new LongFileNameProvider(tmpPath);
		String orig = "longName";
		Assertions.assertEquals(0, countFiles(tmpPath));
		prov.deflate(orig);
		Assertions.assertEquals(1, countFiles(tmpPath));
		prov.deflate(orig);
		Assertions.assertEquals(1, countFiles(tmpPath));
		prov.deflate(orig);
		Assertions.assertEquals(1, countFiles(tmpPath));
		prov.deflate(orig);
		Assertions.assertEquals(1, countFiles(tmpPath));
	}

}
