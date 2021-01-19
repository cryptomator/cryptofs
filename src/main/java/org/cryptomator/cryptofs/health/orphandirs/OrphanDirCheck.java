package org.cryptomator.cryptofs.health.orphandirs;

import org.cryptomator.cryptofs.VaultConfig;
import org.cryptomator.cryptofs.common.Constants;
import org.cryptomator.cryptofs.health.api.CheckFailed;
import org.cryptomator.cryptofs.health.api.DiagnosticResult;
import org.cryptomator.cryptofs.health.api.HealthCheck;
import org.cryptomator.cryptolib.api.Masterkey;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Set;

public class OrphanDirCheck implements HealthCheck {

	private static final Logger LOG = LoggerFactory.getLogger(OrphanDirCheck.class);
	private static final int MAX_TRAVERSAL_DEPTH = 4; // d/2/30/Fo0==.c9r/dir.c9r
	private static final Path DIR_FILE_NAME = Path.of(Constants.DIR_FILE_NAME);
	private static final int MAX_DIR_FILE_SIZE = 36; // limited to 36 ASCII chars as per spec

	@Override
	public Collection<DiagnosticResult> check(Path pathToVault, VaultConfig config, Masterkey masterkey) {
		Path dataDirPath = pathToVault.resolve(Constants.DATA_DIR_NAME);
		var dirVisitor = new DirVisitor();
		try {
			Files.walkFileTree(dataDirPath, Set.of(), MAX_TRAVERSAL_DEPTH, dirVisitor);
		} catch (IOException e) {
			LOG.error("Traversal of data dir failed.", e);
			return List.of(new CheckFailed("Traversal of data dir failed. See log for details."));
		}
		// encrypt-then-hash dirIds
		// find matching dirs (GOOD)
		// report missing d/2/30 dirs as WARN (missing dir -> delete c9r file)
		// report missing dir.c9r files as WARN (orphan dir -> move to L+F)
		return List.of();
	}

	private static class DirVisitor extends SimpleFileVisitor<Path> {

		public final List<String> dirIds = new ArrayList<>(); // contents of all found dir.c9r files
		public final List<Path> secondLevelDirs = new ArrayList<>(); // all d/2/30 dirs

		@Override
		public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) {
			if (DIR_FILE_NAME.equals(file.getFileName())) {
				return visitDirFile(file, attrs);
			}
			return FileVisitResult.CONTINUE;
		}

		private FileVisitResult visitDirFile(Path file, BasicFileAttributes attrs) {
			assert DIR_FILE_NAME.equals(file.getFileName());
			if (attrs.size() > MAX_DIR_FILE_SIZE) {
				// technically not a problem, still not fulfilling specs. what shall we do?
			} else {
				// store content to dirIds
			}
			return FileVisitResult.SKIP_SIBLINGS;
		}

		@Override
		public FileVisitResult preVisitDirectory(Path dir, BasicFileAttributes attrs) throws IOException {
			// if dir is secondLevelDir, store it
			return FileVisitResult.CONTINUE;
		}
	}

}
