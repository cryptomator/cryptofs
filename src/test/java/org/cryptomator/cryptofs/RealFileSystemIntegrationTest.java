/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptofs;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.FileSystem;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.UserPrincipal;

import static org.cryptomator.cryptofs.CryptoFileSystemProperties.cryptoFileSystemProperties;
import static org.cryptomator.cryptofs.CryptoFileSystemUri.create;

public class RealFileSystemIntegrationTest {

	private static Path pathToVault;
	private static FileSystem fileSystem;

	@BeforeAll
	public static void setupClass(@TempDir Path tmpDir) throws IOException {
		pathToVault = tmpDir.resolve("vault");
		Files.createDirectory(pathToVault);
		fileSystem = new CryptoFileSystemProvider().newFileSystem(create(pathToVault), cryptoFileSystemProperties().withPassphrase("asd").build());
	}

	@Test
	public void testReadOwnerUsingFilesGetOwner() throws IOException {
		Assumptions.assumeTrue(FileSystems.getDefault().supportedFileAttributeViews().contains("owner"));

		Path file = fileSystem.getPath("/a");
		Files.write(file, new byte[1]);

		UserPrincipal user = Files.getOwner(file);

		System.out.println(user.getName());
	}

}
