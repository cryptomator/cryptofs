/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptofs.attr;

import com.google.common.jimfs.Jimfs;
import org.cryptomator.cryptofs.CryptoFileSystemProvider;
import org.hamcrest.BaseMatcher;
import org.hamcrest.Description;
import org.hamcrest.Matcher;
import org.hamcrest.MatcherAssert;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.FileSystem;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.BasicFileAttributeView;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.FileTime;
import java.nio.file.attribute.UserPrincipal;
import java.time.Instant;
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

public class FileAttributeIntegrationTest {

	private static FileSystem inMemoryFs;
	private static Path pathToVault;
	private static FileSystem fileSystem;

	@BeforeAll
	public static void setupClass() throws IOException {
		inMemoryFs = Jimfs.newFileSystem();
		pathToVault = inMemoryFs.getRootDirectories().iterator().next().resolve("vault");
		Files.createDirectory(pathToVault);
		fileSystem = new CryptoFileSystemProvider().newFileSystem(create(pathToVault), cryptoFileSystemProperties().withPassphrase("asd").build());
	}

	@AfterAll
	public static void teardownClass() throws IOException {
		inMemoryFs.close();
	}

	@Test
	public void testReadAttributesOfNonExistingFile() throws IOException {
		Path file = fileSystem.getPath("/nonExisting");

		Assertions.assertThrows(NoSuchFileException.class, () -> {
			readAttributes(file, "size,lastModifiedTime,isDirectory");
		});
	}

	@Test
	public void testReadFileAttributesByName() throws IOException {
		Path file = fileSystem.getPath("/a");
		Files.write(file, new byte[1]);

		Map<String, Object> result = Files.readAttributes(file, "size,lastModifiedTime,isDirectory");

		MatcherAssert.assertThat((FileTime) result.get("lastModifiedTime"), is(greaterThan(FileTime.fromMillis(currentTimeMillis() - 10000))));
		MatcherAssert.assertThat((FileTime) result.get("lastModifiedTime"), is(lessThan(FileTime.fromMillis(currentTimeMillis() + 10000))));
		MatcherAssert.assertThat((Long) result.get("size"), is(1L));
		MatcherAssert.assertThat((Boolean) result.get("isDirectory"), is(FALSE));
	}

	@Test
	public void testReadDirectoryAttributesByName() throws IOException {
		Path file = fileSystem.getPath("/b");
		Files.createDirectory(file);

		Map<String, Object> result = Files.readAttributes(file, "lastModifiedTime,isDirectory");

		MatcherAssert.assertThat((FileTime) result.get("lastModifiedTime"), is(greaterThan(FileTime.fromMillis(currentTimeMillis() - 10000))));
		MatcherAssert.assertThat((FileTime) result.get("lastModifiedTime"), is(lessThan(FileTime.fromMillis(currentTimeMillis() + 10000))));
		MatcherAssert.assertThat((Boolean) result.get("isDirectory"), is(TRUE));
	}

	@Test
	public void testReadOwnerUsingFilesGetOwner() throws IOException {
		Assumptions.assumeTrue(inMemoryFs.supportedFileAttributeViews().contains("owner"));

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
			Assertions.assertEquals(t0, t1);
			Thread.sleep(10);

			ch.write(ByteBuffer.wrap(new byte[1])); // write should update the last modified time
			t2 = Files.getLastModifiedTime(file);
			Assertions.assertNotEquals(t2, t1);
			MatcherAssert.assertThat(t2, isAfter(t1));
			Thread.sleep(10);

			ch.force(true); // force must not change the last modified time
			t3 = Files.getLastModifiedTime(file);
			Assertions.assertEquals(t3, t2);
			Thread.sleep(10);
		} // close must not change the last modified time
		t4 = Files.getLastModifiedTime(file); // close after force should not change lastModifiedDate
		Assertions.assertEquals(t3.toMillis(), t4.toMillis()); // round to millis, since in-memory times of opened files may have sub-milli resolution
	}

	@Test
	public void testGetFileSizeWhileStillWritingToNewFile() throws IOException {
		Path file = fileSystem.getPath("/d");

		try (FileChannel ch = FileChannel.open(file, StandardOpenOption.WRITE, StandardOpenOption.CREATE_NEW)) {
			BasicFileAttributes attr1 = Files.readAttributes(file, BasicFileAttributes.class);
			Assertions.assertEquals(0, ch.size());
			Assertions.assertEquals(0, attr1.size());
			Assertions.assertEquals(0, Files.size(file));

			ch.write(ByteBuffer.wrap(new byte[2]));
			BasicFileAttributes attr2 = Files.readAttributes(file, BasicFileAttributes.class);
			Assertions.assertEquals(2, ch.size());
			Assertions.assertEquals(0, attr1.size());
			Assertions.assertEquals(2, attr2.size());
			Assertions.assertEquals(2, Files.size(file));

			ch.write(ByteBuffer.wrap(new byte[2]));
			BasicFileAttributes attr3 = Files.readAttributes(file, BasicFileAttributes.class);
			Assertions.assertEquals(0, attr1.size());
			Assertions.assertEquals(2, attr2.size());
			Assertions.assertEquals(4, attr3.size());
			Assertions.assertEquals(4, ch.size());
			Assertions.assertEquals(4, Files.size(file));
		}
		Assertions.assertEquals(4, Files.size(file));
	}

	@Test
	public void testFileAttributeViewUpdatesAfterMove() throws IOException {
		Path oldpath = fileSystem.getPath("/x");
		Path newpath = fileSystem.getPath("/y");
		try (FileChannel channel = FileChannel.open(oldpath, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE)) {
			BasicFileAttributeView attrView = Files.getFileAttributeView(oldpath, BasicFileAttributeView.class);
			FileTime now = FileTime.from(Instant.ofEpochSecond(123456789L));
			attrView.setTimes(now, null, null);
			Files.move(oldpath, newpath);
			channel.force(true);
			BasicFileAttributeView attrView2 = Files.getFileAttributeView(newpath, BasicFileAttributeView.class);
			Assertions.assertEquals(now, attrView2.readAttributes().lastModifiedTime());

			Assertions.assertThrows(NoSuchFileException.class, () -> {
				attrView.readAttributes();
			});
		}
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
