package org.cryptomator.cryptofs.migration.v7;

import org.cryptomator.cryptofs.common.Constants;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.file.FileVisitResult;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.Optional;

public class VaultStatsVisitor extends SimpleFileVisitor<Path> {
	
	private static final Logger LOG = LoggerFactory.getLogger(VaultStatsVisitor.class);

	private final Path vaultRoot;
	private final boolean determineMaxCiphertextPathLength;
	private long fileCount = 0;
	private long maxPathLength = 0;
	private Path longestNewFile = null;

	public VaultStatsVisitor(Path vaultRoot, boolean determineMaxCiphertextPathLength) {
		this.vaultRoot = vaultRoot;
		this.determineMaxCiphertextPathLength = determineMaxCiphertextPathLength;
	}

	public long getTotalFileCount() {
		return fileCount;
	}


	public Path getLongestNewFile() {
		return longestNewFile;
	}

	public long getMaxCiphertextPathLength() {
		if (determineMaxCiphertextPathLength) {
			return maxPathLength;
		} else {
			return Constants.MAX_CIPHERTEXT_PATH_LENGTH;
		}
	}

	@Override
	public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) throws IOException {
		fileCount++;
		if (determineMaxCiphertextPathLength) {
			try {
				Optional<FilePathMigration> migration = FilePathMigration.parse(vaultRoot, file);
				migration.ifPresent(this::updateMaxCiphertextPathLength);
			} catch (UninflatableFileException e) {
				LOG.warn("SKIP {} because inflation failed.", file);
				return FileVisitResult.CONTINUE;
			}
		}
		return FileVisitResult.CONTINUE;
	}

	private void updateMaxCiphertextPathLength(FilePathMigration filePathMigration) {
		try {
			Path newPath = filePathMigration.getTargetPath("");
			Path relativeToVaultRoot = vaultRoot.relativize(newPath);
			int len = relativeToVaultRoot.toString().length();
			if (len > maxPathLength) {
				maxPathLength = len;
				longestNewFile = newPath;
			}
		} catch (InvalidOldFilenameException e) {
			LOG.warn("Encountered malformed filename.", e);
		}
	}

}
