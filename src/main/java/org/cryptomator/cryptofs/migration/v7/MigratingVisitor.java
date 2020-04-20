package org.cryptomator.cryptofs.migration.v7;

import org.cryptomator.cryptofs.migration.api.MigrationProgressListener;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.FileVisitResult;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Optional;

class MigratingVisitor extends SimpleFileVisitor<Path> {
	
	private static final Logger LOG = LoggerFactory.getLogger(MigratingVisitor.class);

	private final Path vaultRoot;
	private final MigrationProgressListener progressListener;
	private final long estimatedTotalFiles;
	
	public MigratingVisitor(Path vaultRoot, MigrationProgressListener progressListener, long estimatedTotalFiles) {
		this.vaultRoot = vaultRoot;
		this.progressListener = progressListener;
		this.estimatedTotalFiles = estimatedTotalFiles;
	}

	private Collection<FilePathMigration> migrationsInCurrentDir = new ArrayList<>();
	private long migratedFiles = 0;
	
	// Step 1: Collect files to be migrated
	@Override
	public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) throws IOException {
		final Optional<FilePathMigration> migration;
		try {
			migration = FilePathMigration.parse(vaultRoot, file);
		} catch (UninflatableFileException e) {
			LOG.warn("SKIP {} because inflation failed.", file);
			return FileVisitResult.CONTINUE;
		}
		migration.ifPresent(migrationsInCurrentDir::add);
		return FileVisitResult.CONTINUE;
	}

	// Step 2: Only after visiting this dir, we will perform any changes to avoid "ConcurrentModificationExceptions"
	@Override
	public FileVisitResult postVisitDirectory(Path dir, IOException exc) throws IOException {
		for (FilePathMigration migration : migrationsInCurrentDir) {
			migratedFiles++;
			progressListener.update(MigrationProgressListener.ProgressState.MIGRATING, (double) migratedFiles / estimatedTotalFiles);
			try {
				Path migratedFile = migration.migrate();
				LOG.info("MOVED {} to {}", migration.getOldPath(), migratedFile);
			} catch (FileAlreadyExistsException e) {
				LOG.warn("Failed to migrate " + migration.getOldPath() + " due to FileAlreadyExistsException. This can be caused either by sync conflicts or because this file has already been migrated on a different machine.", e);
			}
		}
		migrationsInCurrentDir.clear();
		return FileVisitResult.CONTINUE;
	}
	
}
