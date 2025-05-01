/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptofs.attr;

import com.google.common.jimfs.Configuration;
import com.google.common.jimfs.Jimfs;
import com.google.common.jimfs.PathType;
import org.cryptomator.cryptofs.CryptoFileSystemProperties;
import org.cryptomator.cryptofs.CryptoFileSystemProvider;
import org.cryptomator.cryptolib.api.Masterkey;
import org.cryptomator.cryptolib.api.MasterkeyLoader;
import org.cryptomator.cryptolib.api.MasterkeyLoadingFailedException;
import org.hamcrest.BaseMatcher;
import org.hamcrest.Description;
import org.hamcrest.Matcher;
import org.hamcrest.MatcherAssert;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestMethodOrder;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mockito;

import java.io.IOException;
import java.net.URI;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileSystem;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.BasicFileAttributeView;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.FileTime;
import java.nio.file.attribute.UserDefinedFileAttributeView;
import java.nio.file.attribute.UserPrincipal;
import java.time.Instant;
import java.util.Map;

import static java.lang.Boolean.FALSE;
import static java.lang.Boolean.TRUE;
import static java.lang.System.currentTimeMillis;
import static java.nio.file.Files.readAttributes;
import static org.cryptomator.cryptofs.CryptoFileSystemUri.create;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.Matchers.greaterThan;
import static org.hamcrest.Matchers.lessThan;

public class FileAttributeIntegrationTest {

	private static FileSystem inMemoryFs;
	private static Path pathToVault;
	private static FileSystem fileSystem;

	@BeforeAll
	public static void setupClass() throws IOException, MasterkeyLoadingFailedException {
		inMemoryFs = Jimfs.newFileSystem(Configuration.unix().toBuilder().setAttributeViews("basic", "owner", "user").build());
		pathToVault = inMemoryFs.getRootDirectories().iterator().next().resolve("vault");
		Files.createDirectory(pathToVault);
		MasterkeyLoader keyLoader = Mockito.mock(MasterkeyLoader.class);
		Mockito.when(keyLoader.loadKey(Mockito.any())).thenAnswer(ignored -> new Masterkey(new byte[64]));
		CryptoFileSystemProperties properties = CryptoFileSystemProperties.cryptoFileSystemProperties().withKeyLoader(keyLoader).build();
		CryptoFileSystemProvider.initialize(pathToVault, properties, URI.create("test:key"));
		fileSystem = new CryptoFileSystemProvider().newFileSystem(create(pathToVault), properties);
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

		Assertions.assertNotNull(Files.getOwner(file));
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

	@Nested
	@TestInstance(TestInstance.Lifecycle.PER_CLASS)
	@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
	@DisplayName("Extended Attributes")
	public class UserDefinedFileAttributes {

		private Path file;

		@BeforeAll
		public void setup() throws IOException {
			Assumptions.assumeTrue(inMemoryFs.supportedFileAttributeViews().contains("user"));
			Assumptions.assumeTrue(fileSystem.supportedFileAttributeViews().contains("user"));
			file = fileSystem.getPath("/xattr.txt");
			Files.createFile(file);
		}

		@Order(1)
		@DisplayName("setxattr /xattr.txt")
		@ParameterizedTest(name = "{0}")
		@ValueSource(strings = {"attr1", "attr2", "attr3", "attr4", "attr5"})
		public void testSetxattr(String attrName) throws IOException {
			var attrView = Files.getFileAttributeView(file, UserDefinedFileAttributeView.class);
			var attrValue = StandardCharsets.UTF_8.encode(attrName);

			int written = attrView.write(attrName, attrValue);

			Assertions.assertEquals(attrName.length(), written);
		}

		@Order(2)
		@Test
		@DisplayName("removexattr /xattr.txt")
		public void testRemovexattr() {
			var attrView = Files.getFileAttributeView(file, UserDefinedFileAttributeView.class);

			Assertions.assertDoesNotThrow(() -> attrView.delete("attr3"));
		}

		@Order(3)
		@Test
		@DisplayName("listxattr /xattr.txt")
		public void testListxattr() throws IOException {
			var attrView = Files.getFileAttributeView(file, UserDefinedFileAttributeView.class);
			var result = attrView.list();

			Assertions.assertAll(
					() -> Assertions.assertTrue(result.contains("attr1")),
					() -> Assertions.assertTrue(result.contains("attr2")),
					() -> Assertions.assertFalse(result.contains("attr3")),
					() -> Assertions.assertTrue(result.contains("attr4")),
					() -> Assertions.assertTrue(result.contains("attr5"))
			);
		}

		@Order(4)
		@DisplayName("getxattr")
		@ParameterizedTest(name = "{0}")
		@ValueSource(strings = {"attr1", "attr2", "attr4", "attr5"})
		public void testGetxattr(String attrName) throws IOException {
			var attrView = Files.getFileAttributeView(file, UserDefinedFileAttributeView.class);
			var buffer = ByteBuffer.allocate(attrView.size(attrName));
			var read = attrView.read(attrName, buffer);
			buffer.flip();
			var value = StandardCharsets.UTF_8.decode(buffer).toString();

			Assertions.assertEquals(attrName.length(), read);
			Assertions.assertEquals(attrName, value);
		}

	}


	private static Matcher<FileTime> isAfter(FileTime previousFileTime) {
		return new BaseMatcher<>() {
			@Override
			public boolean matches(Object item) {
				if (item instanceof FileTime ft) {
					return ft.compareTo(previousFileTime) > 0;
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
