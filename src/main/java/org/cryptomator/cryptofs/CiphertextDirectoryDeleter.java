package org.cryptomator.cryptofs;

import static java.nio.file.FileVisitResult.CONTINUE;
import static org.cryptomator.cryptofs.DeleteResult.NO_FILES_EXISTED;
import static org.cryptomator.cryptofs.DeleteResult.SOME_FILES_EXISTED;

import java.io.IOException;
import java.nio.file.DirectoryNotEmptyException;
import java.nio.file.FileVisitResult;
import java.nio.file.FileVisitor;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.concurrent.atomic.AtomicInteger;

import javax.inject.Inject;

@PerProvider
class CiphertextDirectoryDeleter {

	private final EncryptedNamePattern encryptedNamePattern;

	@Inject
	public CiphertextDirectoryDeleter(EncryptedNamePattern encryptedNamePattern) {
		this.encryptedNamePattern = encryptedNamePattern;
	}

	public void deleteCiphertextDirIncludingNonCiphertextFiles(Path ciphertextDir) throws IOException {
		try {
			Files.delete(ciphertextDir);
		} catch (DirectoryNotEmptyException e) {
			switch (deleteNonCiphertextFiles(ciphertextDir)) {
			case NO_FILES_EXISTED:
				throw e;
			case SOME_FILES_EXISTED:
				Files.delete(ciphertextDir);
			}
		}
	}

	private DeleteResult deleteNonCiphertextFiles(Path ciphertextDir) throws IOException {
		AtomicInteger counter = new AtomicInteger(0);
		Files.walkFileTree(ciphertextDir, new FileVisitor<Path>() {

			private int level = 0;

			@Override
			public FileVisitResult preVisitDirectory(Path dir, BasicFileAttributes attrs) throws IOException {
				level++;
				return CONTINUE;
			}

			@Override
			public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) throws IOException {
				if (level > 1 || !isEncryptedFile(file)) {
					counter.incrementAndGet();
					Files.delete(file);
				}
				return CONTINUE;
			}

			private boolean isEncryptedFile(Path file) {
				return encryptedNamePattern.extractEncryptedName(file).isPresent();
			}

			@Override
			public FileVisitResult visitFileFailed(Path file, IOException exc) throws IOException {
				throw exc;
			}

			@Override
			public FileVisitResult postVisitDirectory(Path dir, IOException exc) throws IOException {
				if (exc != null) {
					throw exc;
				}
				level--;
				if (level > 0) {
					Files.delete(dir);
					counter.incrementAndGet();
				}
				return CONTINUE;
			}
		});
		return counter.get() == 0 ? NO_FILES_EXISTED : SOME_FILES_EXISTED;
	}

}
