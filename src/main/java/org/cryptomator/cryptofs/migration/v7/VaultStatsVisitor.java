package org.cryptomator.cryptofs.migration.v7;

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
	private long maxNameLength = 0;
	private long maxPathLength = 0;
	private Path pathWithLongestName = null;
	private Path longestPath = null;

	public VaultStatsVisitor(Path vaultRoot, boolean determineMaxCiphertextPathLength) {
		this.vaultRoot = vaultRoot;
		this.determineMaxCiphertextPathLength = determineMaxCiphertextPathLength;
	}

	public long getTotalFileCount() {
		return fileCount;
	}

	public long getMaxCiphertextNameLength() {
		if (determineMaxCiphertextPathLength) {
			return maxNameLength;
		} else {
			return 220;
		}
	}

	public long getMaxCiphertextPathLength() {
		if (determineMaxCiphertextPathLength) {
			return maxPathLength;
		} else {
			return 268;
		}
	}

	public Path getPathWithLongestName() {
		return pathWithLongestName;
	}

	public Path getLongestPath() {
		return longestPath;
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
			int pathLen = relativeToVaultRoot.toString().length();
			if (pathLen > maxPathLength) {
				maxPathLength = pathLen;
				longestPath = newPath;
			}
			String name = relativeToVaultRoot.getName(3).toString();
			int nameLen = name.length();
			if (nameLen > maxNameLength) {
				maxNameLength = nameLen;
				pathWithLongestName = newPath;
			}
		} catch (InvalidOldFilenameException e) {
			LOG.warn("Encountered malformed filename.", e);
		}
	}

}
