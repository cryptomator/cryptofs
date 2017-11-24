package org.cryptomator.cryptofs;

import static com.google.common.io.MoreFiles.deleteRecursively;
import static com.google.common.io.RecursiveDeleteOption.ALLOW_INSECURE;
import static java.util.stream.Collectors.toSet;
import static org.cryptomator.cryptofs.CiphertextDirectoryDeleter.DeleteResult.NO_FILES_DELETED;
import static org.cryptomator.cryptofs.CiphertextDirectoryDeleter.DeleteResult.SOME_FILES_DELETED;

import java.io.IOException;
import java.nio.file.DirectoryNotEmptyException;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
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
			/*
			 * The directory may not be empty due to two reasons:
			 * 1.
			 * 2.
			 */
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
		DeleteResult result = NO_FILES_DELETED;
		Set<Path> ciphertextFiles = ciphertextFiles(cleartextDir);
		try (DirectoryStream<Path> stream = Files.newDirectoryStream(ciphertextDir, p -> !ciphertextFiles.contains(p))) {
			for (Path path : stream) {
				result = SOME_FILES_DELETED;
				deleteRecursively(path, ALLOW_INSECURE);
			}
		}
		return result;
	}

	private Set<Path> ciphertextFiles(CryptoPath cleartextDir) throws IOException {
		try (CryptoDirectoryStream directoryStream = directoryStreamFactory.newDirectoryStream(cleartextDir, ignored -> true)) {
			return directoryStream.ciphertextDirectoryListing().collect(toSet());
		}
	}

	static enum DeleteResult {
		NO_FILES_DELETED, SOME_FILES_DELETED
	}

}
