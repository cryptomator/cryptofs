/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptofs;

import static java.lang.Boolean.FALSE;
import static java.lang.Boolean.TRUE;
import static java.lang.System.currentTimeMillis;
import static java.nio.file.Files.readAttributes;
import static org.cryptomator.cryptofs.CryptoFileSystemProperties.cryptoFileSystemProperties;
import static org.cryptomator.cryptofs.CryptoFileSystemUris.createUri;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.Matchers.greaterThan;
import static org.hamcrest.Matchers.lessThan;
import static org.junit.Assert.assertThat;
import static org.junit.Assume.assumeThat;

import java.io.IOException;
import java.nio.file.FileSystem;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.attribute.FileTime;
import java.nio.file.attribute.UserPrincipal;
import java.util.Map;

import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import com.google.common.jimfs.Jimfs;

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
		fileSystem = new CryptoFileSystemProvider().newFileSystem(createUri(pathToVault), cryptoFileSystemProperties().withPassphrase("asd").build());
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
		assertThat((Boolean) result.get("directory"), is(TRUE));
	}

	@Test
	public void testReadOwnerUsingFilesGetOwner() throws IOException {
		assumeThat(inMemoryFs.supportedFileAttributeViews().contains("owner"), is(true));

		Path file = fileSystem.getPath("/a");
		Files.write(file, new byte[1]);

		UserPrincipal user = Files.getOwner(file);

		System.out.println(user.getName());
	}

}
