/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptofs;

import com.google.common.jimfs.Jimfs;
import org.hamcrest.BaseMatcher;
import org.hamcrest.Description;
import org.hamcrest.Matcher;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import java.io.File;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.*;
import java.nio.file.attribute.FileTime;
import java.nio.file.attribute.UserPrincipal;
import java.util.Map;

import static java.lang.Boolean.FALSE;
import static java.lang.Boolean.TRUE;
import static java.lang.System.currentTimeMillis;
import static java.nio.file.Files.readAttributes;
import static org.cryptomator.cryptofs.CryptoFileSystemProperties.cryptoFileSystemProperties;
import static org.cryptomator.cryptofs.CryptoFileSystemUri.create;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.Matchers.greaterThan;
import static org.hamcrest.Matchers.lessThan;
import static org.junit.Assert.assertThat;
import static org.junit.Assume.assumeThat;

public class CryptoFileSystemFileAttributeIntegrationTest {

	@Rule
	public ExpectedException thrown = ExpectedException.none();

	private static FileSystem inMemoryFs;
	private static Path pathToVault;
	private static FileSystem fileSystem;

	@BeforeClass
	public static void setupClass() throws IOException {
		inMemoryFs = Jimfs.newFileSystem();
		pathToVault = inMemoryFs.getRootDirectories().iterator().next().resolve("vault");
		Files.createDirectory(pathToVault);
		fileSystem = new CryptoFileSystemProvider().newFileSystem(create(pathToVault), cryptoFileSystemProperties().withPassphrase("asd").build());
	}

	@AfterClass
	public static void teardownClass() throws IOException {
		inMemoryFs.close();
	}

	@Test
	public void testReadAttributesOfNonExistingFile() throws IOException {
		Path file = fileSystem.getPath("/nonExisting");

		thrown.expect(NoSuchFileException.class);

		readAttributes(file, "size,lastModifiedTime,isDirectory");
	}

	@Test
	public void testReadFileAttributesByName() throws IOException {
		Path file = fileSystem.getPath("/a");
		Files.write(file, new byte[1]);

		Map<String, Object> result = Files.readAttributes(file, "size,lastModifiedTime,isDirectory");

		assertThat((FileTime) result.get("lastModifiedTime"), is(greaterThan(FileTime.fromMillis(currentTimeMillis() - 10000))));
		assertThat((FileTime) result.get("lastModifiedTime"), is(lessThan(FileTime.fromMillis(currentTimeMillis() + 10000))));
		assertThat((Long) result.get("size"), is(1L));
		assertThat((Boolean) result.get("isDirectory"), is(FALSE));
	}

	@Test
	public void testReadDirectoryAttributesByName() throws IOException {
		Path file = fileSystem.getPath("/b");
		Files.createDirectory(file);

		Map<String, Object> result = Files.readAttributes(file, "lastModifiedTime,isDirectory");

		assertThat((FileTime) result.get("lastModifiedTime"), is(greaterThan(FileTime.fromMillis(currentTimeMillis() - 10000))));
		assertThat((FileTime) result.get("lastModifiedTime"), is(lessThan(FileTime.fromMillis(currentTimeMillis() + 10000))));
		assertThat((Boolean) result.get("isDirectory"), is(TRUE));
	}

	@Test
	public void testReadOwnerUsingFilesGetOwner() throws IOException {
		assumeThat(inMemoryFs.supportedFileAttributeViews().contains("owner"), is(true));

		Path file = fileSystem.getPath("/a");
		Files.write(file, new byte[1]);

		UserPrincipal user = Files.getOwner(file);

		System.out.println(user.getName());
	}

	@Test
	public void testLastModifiedDateUpdatesOnlyDuringWrite() throws IOException, InterruptedException {
		Path file = fileSystem.getPath("/c");

		FileTime t0, t1, t2, t3, t4;
		try (FileChannel ch = FileChannel.open(file, StandardOpenOption.READ, StandardOpenOption.WRITE, StandardOpenOption.CREATE_NEW)) {
			t0 = Files.getLastModifiedTime(file);
			Thread.sleep(10);

			ch.force(true); // nothing written yet, no changes expected
			t1 = Files.getLastModifiedTime(file);
			Assert.assertEquals(t0, t1);
			Thread.sleep(10);

			ch.write(ByteBuffer.wrap(new byte[1])); // write should update the last modified time
			t2 = Files.getLastModifiedTime(file);
			Assert.assertNotEquals(t2, t1);
			Assert.assertThat(t2, isAfter(t1));
			Thread.sleep(10);

			ch.force(true); // force must not change the last modified time
			t3 = Files.getLastModifiedTime(file);
			Assert.assertEquals(t3, t2);
			Thread.sleep(10);
		} // close must not change the last modified time
		t4 = Files.getLastModifiedTime(file); // close after force should not change lastModifiedDate
		Assert.assertEquals(t3.toMillis(), t4.toMillis()); // round to millis, since in-memory times of opened files may have sub-milli resolution
	}

	private static Matcher<FileTime> isAfter(FileTime previousFileTime) {
		return new BaseMatcher<FileTime>() {
			@Override
			public boolean matches(Object item) {
				if (item instanceof FileTime) {
					FileTime subject = (FileTime) item;
					return subject.compareTo(previousFileTime) > 0;
				} else {
					return false;
				}
			}

			@Override
			public void describeTo(Description description) {
				description.appendText("time after ").appendValue(previousFileTime);
			}
		};
	}

}
