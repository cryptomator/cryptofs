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
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.DirectoryNotEmptyException;
import java.nio.file.FileSystem;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import java.util.stream.Stream;

import static java.nio.file.StandardOpenOption.CREATE_NEW;
import static org.cryptomator.cryptofs.Constants.SHORT_NAMES_MAX_LENGTH;
import static org.cryptomator.cryptofs.CryptoFileSystemProperties.cryptoFileSystemProperties;
import static org.cryptomator.cryptofs.CryptoFileSystemUri.create;

/**
 * Regression tests https://github.com/cryptomator/cryptofs/issues/17.
 */
public class DeleteNonEmptyCiphertextDirectoryIntegrationTest {

	private static Path pathToVault;
	private static Path mDir;
	private static FileSystem fileSystem;

	@BeforeAll
	public static void setupClass(@TempDir Path tmpDir) throws IOException {
		pathToVault = tmpDir.resolve("vault");
		mDir = pathToVault.resolve("m");
		Files.createDirectory(pathToVault);
		fileSystem = new CryptoFileSystemProvider().newFileSystem(create(pathToVault), cryptoFileSystemProperties().withPassphrase("asd").build());
	}

	@Test
	public void testDeleteCiphertextDirectoryContainingNonCryptoFile() throws IOException {
		Path cleartextDirectory = fileSystem.getPath("/z");
		Files.createDirectory(cleartextDirectory);

		Path ciphertextDirectory = firstEmptyCiphertextDirectory();
		createFile(ciphertextDirectory, "foo01234.txt", new byte[] {65});

		Files.delete(cleartextDirectory);
	}

	@Test
	public void testDeleteCiphertextDirectoryContainingDirectories() throws IOException {
		Path cleartextDirectory = fileSystem.getPath("/a");
		Files.createDirectory(cleartextDirectory);

		Path ciphertextDirectory = firstEmptyCiphertextDirectory();
		// ciphertextDir
		// .. foo0123
		// .... foobar
		// ...... test.baz
		// .... text.txt
		// .... text.data
		Path foo0123 = createFolder(ciphertextDirectory, "foo0123");
		Path foobar = createFolder(foo0123, "foobar");
		createFile(foo0123, "test.txt", new byte[] {65});
		createFile(foo0123, "text.data", new byte[] {65});
		createFile(foobar, "test.baz", new byte[] {65});

		Files.delete(cleartextDirectory);
	}

	@Test
	public void testDeleteDirectoryContainingLongNameFileWithoutMetadata() throws IOException {
		Path cleartextDirectory = fileSystem.getPath("/b");
		Files.createDirectory(cleartextDirectory);

		Path ciphertextDirectory = firstEmptyCiphertextDirectory();
		createFile(ciphertextDirectory, "HHEZJURE.lng", new byte[] {65});

		Files.delete(cleartextDirectory);
	}

	@Test
	public void testDeleteDirectoryContainingUnauthenticLongNameDirectoryFile() throws IOException {
		Path cleartextDirectory = fileSystem.getPath("/c");
		Files.createDirectory(cleartextDirectory);

		Path ciphertextDirectory = firstEmptyCiphertextDirectory();
		createFile(ciphertextDirectory, "HHEZJURE.lng", new byte[] {65});
		Path mSubdir = mDir.resolve("HH").resolve("EZ");
		Files.createDirectories(mSubdir);
		createFile(mSubdir, "HHEZJURE.lng", "0HHEZJUREHHEZJUREHHEZJURE".getBytes());

		Files.delete(cleartextDirectory);
	}

	@Test
	public void testDeleteNonEmptyDir() throws IOException {
		Path cleartextDirectory = fileSystem.getPath("/d");
		Files.createDirectory(cleartextDirectory);
		createFile(cleartextDirectory, "test", new byte[] {65});

		Assertions.assertThrows(DirectoryNotEmptyException.class, () -> {
			Files.delete(cleartextDirectory);
		});
	}

	@Test
	public void testDeleteDirectoryContainingLongNamedDirectory() throws IOException {
		Path cleartextDirectory = fileSystem.getPath("/e");
		Files.createDirectory(cleartextDirectory);

		// a
		// .. LongNameaaa...
		String name = "LongName" + IntStream.range(0, SHORT_NAMES_MAX_LENGTH) //
				.mapToObj(ignored -> "a") //
				.collect(Collectors.joining());
		createFolder(cleartextDirectory, name);

		Assertions.assertThrows(DirectoryNotEmptyException.class, () -> {
			Files.delete(cleartextDirectory);
		});
	}

	@Test
	public void testDeleteEmptyDir() throws IOException {
		Path cleartextDirectory = fileSystem.getPath("/f");
		Files.createDirectory(cleartextDirectory);

		Files.delete(cleartextDirectory);
	}

	private Path firstEmptyCiphertextDirectory() throws IOException {
		try (Stream<Path> allFilesInVaultDir = Files.walk(pathToVault)) {
			return allFilesInVaultDir //
					.filter(Files::isDirectory) //
					.filter(this::isEmptyDirectory) //
					.filter(this::isEncryptedDirectory) //
					.findFirst() //
					.get();
		}
	}

	private boolean isEmptyDirectory(Path path) {
		try (Stream<Path> files = Files.list(path)) {
			return files.count() == 0;
		} catch (IOException e) {
			throw new UncheckedIOException(e);
		}
	}

	private boolean isEncryptedDirectory(Path pathInVault) {
		Path relativePath = pathToVault.relativize(pathInVault);
		String relativePathAsString = relativePath.toString().replace(File.separatorChar, '/');
		return relativePathAsString.matches("d/[2-7A-Z]{2}/[2-7A-Z]{30}");
	}

	private Path createFolder(Path parent, String name) throws IOException {
		Path result = parent.resolve(name);
		Files.createDirectory(result);
		return result;
	}

	private Path createFile(Path parent, String name, byte[] data) throws IOException {
		Path result = parent.resolve(name);
		Files.write(result, data, CREATE_NEW);
		return result;
	}

}
