package org.cryptomator.cryptofs;

import java.io.IOException;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.Collections;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

public class LongFileNameProviderTest {

	private Path tmpPath;

	@Before
	public void setup() throws IOException {
		tmpPath = Files.createTempDirectory("unit-tests");
	}

	@After
	public void teardown() throws IOException {
		Files.walkFileTree(tmpPath, new DeletingFileVisitor());
	}

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
	public void testIsDeflated() throws IOException {
		Assert.assertTrue(LongFileNameProvider.isDeflated("foo.lng"));
		Assert.assertFalse(LongFileNameProvider.isDeflated("foo.txt"));
	}

	@Test
	public void testDeflateAndInflate() throws IOException {
		String orig = "longName";
		Assert.assertEquals(0, countFiles(tmpPath));
		LongFileNameProvider prov1 = new LongFileNameProvider(tmpPath);
		String deflated = prov1.deflate(orig);
		Assert.assertEquals(1, countFiles(tmpPath));
		LongFileNameProvider prov2 = new LongFileNameProvider(tmpPath);
		String inflated = prov2.inflate(deflated);
		Assert.assertEquals(orig, inflated);
	}

	@Test(expected = IOException.class)
	public void testInflateNonExisting() throws IOException {
		LongFileNameProvider prov = new LongFileNameProvider(tmpPath);
		prov.inflate("doesNotExist");
	}

	@Test
	public void testDeflateMultipleTimes() throws IOException {
		LongFileNameProvider prov = new LongFileNameProvider(tmpPath);
		String orig = "longName";
		Assert.assertEquals(0, countFiles(tmpPath));
		prov.deflate(orig);
		Assert.assertEquals(1, countFiles(tmpPath));
		prov.deflate(orig);
		Assert.assertEquals(1, countFiles(tmpPath));
		prov.deflate(orig);
		Assert.assertEquals(1, countFiles(tmpPath));
		prov.deflate(orig);
		Assert.assertEquals(1, countFiles(tmpPath));
	}

}
