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
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledOnOs;
import org.junit.jupiter.api.condition.OS;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.Mockito;

import java.io.IOException;
import java.net.URI;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileSystem;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributeView;
import java.nio.file.attribute.FileTime;
import java.nio.file.attribute.UserPrincipal;
import java.time.Instant;

import static org.cryptomator.cryptofs.CryptoFileSystemProperties.cryptoFileSystemProperties;
import static java.nio.file.StandardOpenOption.CREATE_NEW;
import static java.nio.file.StandardOpenOption.DELETE_ON_CLOSE;
import static java.nio.file.StandardOpenOption.READ;
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

	@Nested
	@DisplayName("Modification time of a ciphertext changed in place while the file is open")
	class TimeAfterChangeInPlace {

		private static final int SIZE = 5 * 32 * 1024;
		private static final FileTime FOREIGN_TIME = FileTime.from(Instant.parse("2031-03-04T05:06:07Z"));
		private static final FileTime VIEW_TIME = FileTime.from(Instant.parse("2029-01-02T03:04:05Z"));

		private Path newFile(String name) throws IOException {
			Path file = fileSystem.getPath(name);
			Files.write(file, new byte[SIZE]);
			return file;
		}

		private Path ciphertextOf(Path file) throws IOException {
			return ((CryptoFileSystem) fileSystem).getCiphertextPath(file);
		}

		private void changeInPlace(Path ciphertext, FileTime time) throws IOException {
			try (var raw = FileChannel.open(ciphertext, READ, WRITE)) {
				var lastChunkByte = ByteBuffer.allocate(1);
				raw.read(lastChunkByte, raw.size() - 1);
				raw.write(lastChunkByte.flip(), raw.size() - 1);
			}
			Files.setLastModifiedTime(ciphertext, time);
		}

		@Test
		@DisplayName("A channel that wrote nothing keeps another process's time")
		public void testChannelWithoutWriteKeepsForeignTime() throws IOException {
			Path file = newFile("/timeNoWrite");
			Path ciphertext = ciphertextOf(file);

			try (var ch = FileChannel.open(file, READ, WRITE)) {
				ch.read(ByteBuffer.allocate(100), 0);
				changeInPlace(ciphertext, FOREIGN_TIME);
			}

			Assertions.assertEquals(FOREIGN_TIME, Files.getLastModifiedTime(ciphertext));
		}

		@Test
		@DisplayName("A channel that saved before the change keeps another process's time")
		public void testChannelSavedBeforeChangeKeepsForeignTime() throws IOException {
			Path file = newFile("/timeForced");
			Path ciphertext = ciphertextOf(file);

			try (var ch = FileChannel.open(file, READ, WRITE)) {
				ch.write(ByteBuffer.wrap(new byte[]{'x'}), 100);
				ch.force(false);
				changeInPlace(ciphertext, FOREIGN_TIME);
			}

			Assertions.assertEquals(FOREIGN_TIME, Files.getLastModifiedTime(ciphertext));
		}

		@Test
		@DisplayName("Saving a dirty chunk next to a change of another chunk doesn't move the time back to the write's")
		public void testDirtyChunkNextToForeignChange() throws IOException, InterruptedException {
			Path file = newFile("/timeDirty");
			Path ciphertext = ciphertextOf(file);
			FileTime foreignTime;

			try (var ch = FileChannel.open(file, READ, WRITE)) {
				ch.write(ByteBuffer.wrap(new byte[]{'x'}), 100);
				Thread.sleep(50);
				changeInPlace(ciphertext, FileTime.from(Instant.now()));
				foreignTime = Files.getLastModifiedTime(ciphertext); // as stored, in the file system's precision
			}

			Assertions.assertTrue(Files.getLastModifiedTime(ciphertext).compareTo(foreignTime) >= 0);
		}

		@Test
		@DisplayName("A foreign time after a time set through the view is kept")
		public void testForeignTimeAfterViewTime() throws IOException {
			Path file = newFile("/timeViewThenForeign");
			Path ciphertext = ciphertextOf(file);

			try (var ch = FileChannel.open(file, READ, WRITE)) {
				ch.write(ByteBuffer.wrap(new byte[]{'x'}), 100);
				ch.force(false);
				Files.setLastModifiedTime(file, VIEW_TIME);
				changeInPlace(ciphertext, FOREIGN_TIME);
			}

			Assertions.assertEquals(FOREIGN_TIME, Files.getLastModifiedTime(ciphertext));
		}

		@Test
		@DisplayName("An access time update doesn't make a foreign time this file's own")
		public void testAccessTimeUpdateKeepsForeignTime() throws IOException {
			Path file = newFile("/timeAccess");
			Path ciphertext = ciphertextOf(file);

			try (var ch = FileChannel.open(file, READ, WRITE)) {
				ch.write(ByteBuffer.wrap(new byte[]{'x'}), 100);
				ch.force(false);
				changeInPlace(ciphertext, FOREIGN_TIME);
				Files.getFileAttributeView(file, BasicFileAttributeView.class).setTimes(null, FileTime.from(Instant.now()), null);
			}

			Assertions.assertEquals(FOREIGN_TIME, Files.getLastModifiedTime(ciphertext));
		}

		@Test
		@DisplayName("Without a foreign change, the time of the write persists")
		public void testOwnWriteTimePersists() throws IOException, InterruptedException {
			Path file = newFile("/timeOwnWrite");
			Path ciphertext = ciphertextOf(file);
			Instant afterWrite;

			try (var ch = FileChannel.open(file, READ, WRITE)) {
				ch.write(ByteBuffer.wrap(new byte[]{'x'}), 100);
				afterWrite = Instant.now();
				Thread.sleep(50);
			}

			Assertions.assertFalse(Files.getLastModifiedTime(ciphertext).toInstant().isAfter(afterWrite));
		}

		@Test
		@DisplayName("A time set through the view persists")
		public void testViewTimePersists() throws IOException {
			Path file = newFile("/timeView");
			Path ciphertext = ciphertextOf(file);

			try (var ch = FileChannel.open(file, READ, WRITE)) {
				ch.write(ByteBuffer.wrap(new byte[]{'x'}), 100);
				Files.setLastModifiedTime(file, VIEW_TIME);
			}

			Assertions.assertEquals(VIEW_TIME, Files.getLastModifiedTime(ciphertext));
		}

	}

}
