/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptofs;

import static java.nio.file.Files.walkFileTree;
import static org.cryptomator.cryptofs.CryptoFileSystemProperties.cryptoFileSystemProperties;
import static org.cryptomator.cryptofs.CryptoFileSystemUri.create;
import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assume.assumeThat;

import java.io.IOException;
import java.nio.file.FileSystem;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.UserPrincipal;

import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

public class RealFileSystemIntegrationTest {

	@Rule
	public ExpectedException thrown = ExpectedException.none();

	private static Path tempDir;
	private static Path pathToVault;
	private static FileSystem fileSystem;

	@BeforeClass
	public static void setupClass() throws IOException {
		tempDir = Files.createTempDirectory("RealFileSystemIntegrationTest");
		pathToVault = tempDir.resolve("vault");
		Files.createDirectory(pathToVault);
		fileSystem = new CryptoFileSystemProvider().newFileSystem(create(pathToVault), cryptoFileSystemProperties().withPassphrase("asd").build());
	}

	@AfterClass
	public static void teardownClass() throws IOException {
		walkFileTree(tempDir, DeletingFileVisitor.INSTANCE);
	}

	@Test
	public void testReadOwnerUsingFilesGetOwner() throws IOException {
		assumeThat(FileSystems.getDefault().supportedFileAttributeViews().contains("owner"), is(true));

		Path file = fileSystem.getPath("/a");
		Files.write(file, new byte[1]);

		UserPrincipal user = Files.getOwner(file);

		System.out.println(user.getName());
	}

}
