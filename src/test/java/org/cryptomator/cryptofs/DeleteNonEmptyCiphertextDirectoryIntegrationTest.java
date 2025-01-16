/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptofs;

import com.google.common.base.Strings;
import org.cryptomator.cryptofs.common.Constants;
import org.cryptomator.cryptolib.api.Masterkey;
import org.cryptomator.cryptolib.api.MasterkeyLoader;
import org.cryptomator.cryptolib.api.MasterkeyLoadingFailedException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.Mockito;

import java.io.File;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.URI;
import java.nio.file.DirectoryNotEmptyException;
import java.nio.file.FileSystem;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.function.Predicate;
import java.util.stream.Stream;

import static java.nio.file.StandardOpenOption.CREATE_NEW;
import static org.cryptomator.cryptofs.CryptoFileSystemUri.create;

/**
 * Regression tests https://github.com/cryptomator/cryptofs/issues/17.
 */
public class DeleteNonEmptyCiphertextDirectoryIntegrationTest {

	private static Path pathToVault;
	private static FileSystem fileSystem;

	@BeforeAll
	public static void setupClass(@TempDir Path tmpDir) throws IOException, MasterkeyLoadingFailedException {
		pathToVault = tmpDir.resolve("vault");
		Files.createDirectory(pathToVault);
		MasterkeyLoader keyLoader = Mockito.mock(MasterkeyLoader.class);
		Mockito.when(keyLoader.loadKey(Mockito.any())).thenAnswer(ignored -> new Masterkey(new byte[64]));
		CryptoFileSystemProperties properties = CryptoFileSystemProperties.cryptoFileSystemProperties().withKeyLoader(keyLoader).build();
		CryptoFileSystemProvider.initialize(pathToVault, properties, URI.create("test:key"));
		fileSystem = new CryptoFileSystemProvider().newFileSystem(create(pathToVault), properties);
	}

	@Test
	public void testDeleteCiphertextDirectoryContainingNonCryptoFile() throws IOException {
		Path cleartextDirectory = fileSystem.getPath("/z");
		Files.createDirectory(cleartextDirectory);

		Path ciphertextDirectory = firstEmptyCiphertextDirectory();
		createFile(ciphertextDirectory, "foo01234.txt", new byte[]{65});

		Assertions.assertDoesNotThrow(() -> {
			Files.delete(cleartextDirectory);
		});
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
		createFile(foo0123, "test.txt", new byte[]{65});
		createFile(foo0123, "text.data", new byte[]{65});
		createFile(foobar, "test.baz", new byte[]{65});

		Assertions.assertDoesNotThrow(() -> {
			Files.delete(cleartextDirectory);
		});
	}

	@Test
	@Disabled // c9s not yet implemented
	public void testDeleteDirectoryContainingLongNameFileWithoutMetadata() throws IOException {
		Path cleartextDirectory = fileSystem.getPath("/b");
		Files.createDirectory(cleartextDirectory);

		Path ciphertextDirectory = firstEmptyCiphertextDirectory();
		Path longNameDir = createFolder(ciphertextDirectory, "HHEZJURE.c9s");
		createFile(longNameDir, Constants.CONTENTS_FILE_NAME, new byte[]{65});

		Assertions.assertDoesNotThrow(() -> {
			Files.delete(cleartextDirectory);
		});
	}

	@Test
	@Disabled // c9s not yet implemented
	public void testDeleteDirectoryContainingUnauthenticLongNameDirectoryFile() throws IOException {
		Path cleartextDirectory = fileSystem.getPath("/c");
		Files.createDirectory(cleartextDirectory);

		Path ciphertextDirectory = firstEmptyCiphertextDirectory();
		Path longNameDir = createFolder(ciphertextDirectory, "HHEZJURE.c9s");
		createFile(longNameDir, Constants.INFLATED_FILE_NAME, "HHEZJUREHHEZJUREHHEZJURE".getBytes());
		createFile(longNameDir, Constants.CONTENTS_FILE_NAME, new byte[]{65});

		Assertions.assertDoesNotThrow(() -> {
			Files.delete(cleartextDirectory);
		});
	}

	@Test
	public void testDeleteNonEmptyDir() throws IOException {
		Path cleartextDirectory = fileSystem.getPath("/d");
		Files.createDirectory(cleartextDirectory);
		createFile(cleartextDirectory, "test", new byte[]{65});

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
		String name = "LongName" + Strings.repeat("a", CryptoFileSystemProperties.DEFAULT_SHORTENING_THRESHOLD);
		createFolder(cleartextDirectory, name);

		Assertions.assertThrows(DirectoryNotEmptyException.class, () -> {
			Files.delete(cleartextDirectory);
		});
	}

	@Test
	public void testDeleteEmptyDir() throws IOException {
		Path cleartextDirectory = fileSystem.getPath("/f");
		Files.createDirectory(cleartextDirectory);

		Assertions.assertDoesNotThrow(() -> {
			Files.delete(cleartextDirectory);
		});
	}

	private Path firstEmptyCiphertextDirectory() throws IOException {
		try (Stream<Path> allFilesInVaultDir = Files.walk(pathToVault)) {
			return allFilesInVaultDir //
					.filter(Files::isDirectory) //
					.filter(this::isEmptyCryptoFsDirectory) //
					.filter(this::isEncryptedDirectory) //
					.findFirst() //
					.get();
		}
	}

	private boolean isEmptyCryptoFsDirectory(Path path) {
		Predicate<Path> isIgnoredFile = p -> Constants.DIR_ID_BACKUP_FILE_NAME.equals(p.getFileName().toString());
		try (Stream<Path> files = Files.list(path)) {
			return files.noneMatch(isIgnoredFile.negate());
		} catch (IOException e) {
			throw new UncheckedIOException(e);
		}
	}

	@Test
	@DisplayName("Tests internal cryptofs directory emptiness definition")
	public void testCryptoFsDirEmptiness() throws IOException {
		var emptiness = pathToVault.getParent().resolve("emptiness");
		var ignoredFile = emptiness.resolve(Constants.DIR_ID_BACKUP_FILE_NAME);
		Files.createDirectory(emptiness);
		Files.createFile(ignoredFile);

		boolean result = isEmptyCryptoFsDirectory(emptiness);

		Assertions.assertTrue(result, "Ciphertext directory containing only dirId-file should be accepted as an empty dir");
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
