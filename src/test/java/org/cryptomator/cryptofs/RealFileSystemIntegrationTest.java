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
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledOnOs;
import org.junit.jupiter.api.condition.OS;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.Mockito;

import java.io.IOException;
import java.net.URI;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileSystem;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.UserPrincipal;

import static org.cryptomator.cryptofs.CryptoFileSystemProperties.cryptoFileSystemProperties;
import static java.nio.file.StandardOpenOption.CREATE_NEW;
import static java.nio.file.StandardOpenOption.DELETE_ON_CLOSE;
import static java.nio.file.StandardOpenOption.WRITE;
import static org.cryptomator.cryptofs.CryptoFileSystemUri.create;

public class RealFileSystemIntegrationTest {

	private static Path pathToVault;
	private static FileSystem fileSystem;

	@BeforeAll
	public static void setupClass(@TempDir Path tmpDir) throws IOException, MasterkeyLoadingFailedException {
		pathToVault = tmpDir.resolve("vault");
		Files.createDirectory(pathToVault);
		MasterkeyLoader keyLoader = Mockito.mock(MasterkeyLoader.class);
		Mockito.when(keyLoader.loadKey(Mockito.any())).thenAnswer(ignored -> new Masterkey(new byte[64]));
		CryptoFileSystemProperties properties = cryptoFileSystemProperties().withKeyLoader(keyLoader).build();
		CryptoFileSystemProvider.initialize(pathToVault, properties, URI.create("test:key"));
		fileSystem = new CryptoFileSystemProvider().newFileSystem(create(pathToVault), properties);
	}

	@Test
	public void testReadOwnerUsingFilesGetOwner() throws IOException {
		Assumptions.assumeTrue(FileSystems.getDefault().supportedFileAttributeViews().contains("owner"));

		Path file = fileSystem.getPath("/a");
		Files.write(file, new byte[1]);

		Assertions.assertNotNull(Files.getOwner(file));
	}

	@Test
	@EnabledOnOs({OS.MAC, OS.LINUX}) // Windows deletes on close, not at open
	@DisplayName("A file opened with DELETE_ON_CLOSE can be created again while it is open")
	public void testRecreateFileOpenedWithDeleteOnClose() throws IOException {
		Path file = fileSystem.getPath("/deleteOnClose");
		try (var ch = FileChannel.open(file, CREATE_NEW, WRITE, DELETE_ON_CLOSE)) {
			ch.write(StandardCharsets.UTF_8.encode("deleted"));
			try (var ch2 = FileChannel.open(file, CREATE_NEW, WRITE)) {
				ch2.write(StandardCharsets.UTF_8.encode("recreated"));
			}
		}

		Assertions.assertEquals("recreated", Files.readString(file));
	}

}
