package org.cryptomator.cryptofs;

import javax.inject.Inject;
import java.io.IOException;
import java.nio.file.DirectoryNotEmptyException;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Set;

import static java.util.stream.Collectors.toSet;
import static org.cryptomator.cryptofs.CiphertextDirectoryDeleter.DeleteResult.NO_FILES_DELETED;
import static org.cryptomator.cryptofs.CiphertextDirectoryDeleter.DeleteResult.SOME_FILES_DELETED;

@CryptoFileSystemScoped
class CiphertextDirectoryDeleter {

	private final DirectoryStreamFactory directoryStreamFactory;

	@Inject
	public CiphertextDirectoryDeleter(DirectoryStreamFactory directoryStreamFactory) {
		this.directoryStreamFactory = directoryStreamFactory;
	}

	public void deleteCiphertextDirIncludingNonCiphertextFiles(Path ciphertextDir, CryptoPath cleartextDir) throws IOException {
		try {
			DeletingFileVisitor.forceDeleteIfExists(ciphertextDir);
		} catch (DirectoryNotEmptyException e) {
			/*
			 * The directory may not be empty due to two reasons:
			 * 1. The directory really contains some valid ciphertext files
			 * 2. The directory does only contain files which are no cyphertext files
			 *
			 * In the first case the exception must be rethrown. In the second case the non cyphertext files and the
			 * directory must be deleted.
			 *
			 * Because we do not know at this point what is true we try to delete all non ciphertext files. If no non
			 * ciphertext files were deleted, we know that case 1 is true. If we deleted non ciphertext files both,
			 * case 1 or 2 could be true, thus we then reattempt the delete of the directory. If delete fails now, we
			 * can be sure that case 1 was true. Otherwise the exception is directly thrown because we are sure that
			 * case 2 is true.
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
				Files.walkFileTree(path, DeletingFileVisitor.INSTANCE);
			}
		}
		return result;
	}

	private Set<Path> ciphertextFiles(CryptoPath cleartextDir) throws IOException {
		try (CryptoDirectoryStream directoryStream = directoryStreamFactory.newDirectoryStream(cleartextDir, ignored -> true)) {
			return directoryStream.ciphertextDirectoryListing().collect(toSet());
		}
	}

	enum DeleteResult {
		NO_FILES_DELETED, SOME_FILES_DELETED
	}

}
