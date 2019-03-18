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
import java.net.URI;
import java.nio.file.FileSystem;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

public class ReadmeCodeSamplesTest {

	@Test
	public void testReadmeCodeSampleUsingFileSystemConstructionMethodA(@TempDir Path storageLocation) throws IOException {
		FileSystem fileSystem = CryptoFileSystemProvider.newFileSystem(storageLocation, CryptoFileSystemProperties.cryptoFileSystemProperties().withPassphrase("password").build());

		runCodeSample(fileSystem);
	}

	@Test
	public void testReadmeCodeSampleUsingFileSystemConstructionMethodB(@TempDir Path storageLocation) throws IOException {
		URI uri = CryptoFileSystemUri.create(storageLocation);
		FileSystem fileSystem = FileSystems.newFileSystem(uri, CryptoFileSystemProperties.cryptoFileSystemProperties().withPassphrase("password").build());

		runCodeSample(fileSystem);
	}

	private void runCodeSample(FileSystem fileSystem) throws IOException {
		// obtain a path to a test file
		Path testFile = fileSystem.getPath("/foo/bar/test");

		// create all parent directories
		Files.createDirectories(testFile.getParent());

		// Write data to the file
		Files.write(testFile, "test".getBytes());

		// List all files present in a directory
		List<Path> files = new ArrayList<>();
		try (Stream<Path> listing = Files.list(testFile.getParent())) {
			listing.forEach(files::add);
		}

		Assertions.assertEquals(1, files.size());
		Assertions.assertEquals("/foo/bar/test", files.get(0).toString());
		Assertions.assertEquals(Files.size(testFile), 4);
	}

}
