/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptofs;

import org.cryptomator.cryptolib.api.Masterkey;
import org.cryptomator.cryptolib.api.MasterkeyLoader;
import org.cryptomator.cryptolib.api.MasterkeyLoadingFailedException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.Mockito;

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
	public void testReadmeCodeSampleUsingFileSystemConstructionMethodA(@TempDir Path storageLocation) throws IOException, MasterkeyLoadingFailedException {
		MasterkeyLoader keyLoader = Mockito.mock(MasterkeyLoader.class);
		Mockito.when(keyLoader.supportsScheme("test")).thenReturn(true);
		Mockito.when(keyLoader.loadKey(Mockito.any())).thenReturn(Masterkey.createFromRaw(new byte[64]));
		CryptoFileSystemProperties properties = CryptoFileSystemProperties.cryptoFileSystemProperties().withKeyLoaders(keyLoader).build();
		CryptoFileSystemProvider.initialize(storageLocation, properties, URI.create("test:key"));
		FileSystem fileSystem = CryptoFileSystemProvider.newFileSystem(storageLocation, properties);

		runCodeSample(fileSystem);
	}

	@Test
	public void testReadmeCodeSampleUsingFileSystemConstructionMethodB(@TempDir Path storageLocation) throws IOException, MasterkeyLoadingFailedException {
		URI uri = CryptoFileSystemUri.create(storageLocation);
		MasterkeyLoader keyLoader = Mockito.mock(MasterkeyLoader.class);
		Mockito.when(keyLoader.supportsScheme("test")).thenReturn(true);
		Mockito.when(keyLoader.loadKey(Mockito.any())).thenReturn(Masterkey.createFromRaw(new byte[64]));
		CryptoFileSystemProperties properties = CryptoFileSystemProperties.cryptoFileSystemProperties().withKeyLoaders(keyLoader).build();
		CryptoFileSystemProvider.initialize(storageLocation, properties, URI.create("test:key"));
		FileSystem fileSystem = FileSystems.newFileSystem(uri, properties);

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
