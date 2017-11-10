package org.cryptomator.cryptofs;

import static java.nio.file.FileVisitResult.CONTINUE;
import static java.util.stream.Collectors.toSet;
import static org.cryptomator.cryptofs.CiphertextDirectoryDeleter.DeleteResult.NO_FILES_DELETED;
import static org.cryptomator.cryptofs.CiphertextDirectoryDeleter.DeleteResult.SOME_FILES_DELETED;

import java.io.IOException;
import java.nio.file.DirectoryNotEmptyException;
import java.nio.file.FileVisitResult;
import java.nio.file.FileVisitor;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.Set;

import javax.inject.Inject;

@PerFileSystem
class CiphertextDirectoryDeleter {

	private final DirectoryStreamFactory directoryStreamFactory;

	@Inject
	public CiphertextDirectoryDeleter(DirectoryStreamFactory directoryStreamFactory) {
		this.directoryStreamFactory = directoryStreamFactory;
	}

	public void deleteCiphertextDirIncludingNonCiphertextFiles(Path ciphertextDir, CryptoPath cleartextDir) throws IOException {
		try {
			Files.deleteIfExists(ciphertextDir);
		} catch (DirectoryNotEmptyException e) {
			switch (deleteNonCiphertextFiles(ciphertextDir, cleartextDir)) {
			case NO_FILES_DELETED:
				throw e;
			case SOME_FILES_DELETED:
				Files.delete(ciphertextDir);
				break;
			default:
				throw new IllegalStateException("Unexpected enum constant");
			}
		}
	}

	private DeleteResult deleteNonCiphertextFiles(Path ciphertextDir, CryptoPath cleartextDir) throws IOException {
		NonCiphertextFilesDeletingFileVisitor visitor;
		try (CryptoDirectoryStream directoryStream = directoryStreamFactory.newDirectoryStream(cleartextDir, ignored -> true)) {
			Set<Path> ciphertextFiles = directoryStream.ciphertextDirectoryListing().collect(toSet());
			visitor = new NonCiphertextFilesDeletingFileVisitor(ciphertextFiles);
		}
		Files.walkFileTree(ciphertextDir, visitor);
		return visitor.getNumDeleted() == 0 //
				? NO_FILES_DELETED //
				: SOME_FILES_DELETED;
	}

	static enum DeleteResult {
		NO_FILES_DELETED, SOME_FILES_DELETED
	}

	private static class NonCiphertextFilesDeletingFileVisitor implements FileVisitor<Path> {

		private final Set<Path> ciphertextFiles;

		private int numDeleted = 0;
		private int level = 0;

		public NonCiphertextFilesDeletingFileVisitor(Set<Path> ciphertextFiles) {
			this.ciphertextFiles = ciphertextFiles;
		}

		public int getNumDeleted() {
			return numDeleted;
		}

		@Override
		public FileVisitResult preVisitDirectory(Path dir, BasicFileAttributes attrs) throws IOException {
			level++;
			return CONTINUE;
		}

		@Override
		public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) throws IOException {
			if (!isOnRootLevel() || !isCiphertextFile(file)) {
				Files.delete(file);
				numDeleted++;
			}
			return CONTINUE;
		}

		private boolean isOnRootLevel() {
			return level == 1;
		}

		private boolean isCiphertextFile(Path file) throws IOException {
			return ciphertextFiles.contains(file);
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
				numDeleted++;
			}
			return CONTINUE;
		}
	};

}
