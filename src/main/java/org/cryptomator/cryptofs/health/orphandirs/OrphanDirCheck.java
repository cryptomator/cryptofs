package org.cryptomator.cryptofs.health.orphandirs;

import org.cryptomator.cryptofs.VaultConfig;
import org.cryptomator.cryptofs.common.Constants;
import org.cryptomator.cryptofs.health.api.CheckFailed;
import org.cryptomator.cryptofs.health.api.DiagnosticResult;
import org.cryptomator.cryptofs.health.api.HealthCheck;
import org.cryptomator.cryptolib.api.Cryptor;
import org.cryptomator.cryptolib.api.Masterkey;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class OrphanDirCheck implements HealthCheck {

	private static final Logger LOG = LoggerFactory.getLogger(OrphanDirCheck.class);
	private static final int MAX_TRAVERSAL_DEPTH = 4; // d/2/30/Fo0==.c9r/dir.c9r
	private static final Path DIR_FILE_NAME = Path.of(Constants.DIR_FILE_NAME);

	@Override
	public Collection<DiagnosticResult> check(Path pathToVault, VaultConfig config, Masterkey masterkey, Cryptor cryptor) {
		var result = new ArrayList<DiagnosticResult>();

		// scan vault structure:
		Path dataDirPath = pathToVault.resolve(Constants.DATA_DIR_NAME);
		var dirVisitor = new DirVisitor(dataDirPath);
		try {
			Files.walkFileTree(dataDirPath, Set.of(), MAX_TRAVERSAL_DEPTH, dirVisitor);
		} catch (IOException e) {
			LOG.error("Traversal of data dir failed.", e);
			return List.of(new CheckFailed("Traversal of data dir failed. See log for details."));
		}

		// remove matching pairs:
		int healthyDirs = 0;
		var iter = dirVisitor.dirIds.iterator();
		while (iter.hasNext()) {
			var dirId = iter.next();
			var hashedDirId = cryptor.fileNameCryptor().hashDirectoryId(dirId);
			var expectedDir = Path.of(hashedDirId.substring(0, 2), hashedDirId.substring(2));
			boolean foundDir = dirVisitor.secondLevelDirs.remove(expectedDir);
			if (foundDir) {
				healthyDirs++;
				iter.remove();
				// TODO: result.add(GOOD)
			}
		}

		// TODO: result.add(WARN) for each remaining:
		// dirVisitor.dirIds contains dirIds with missing dirs (can be deleted)
		// dirVisitor.secondLevelDirs contains orphan dirs (can be moved to L+F)
		LOG.info("Ran OrphanDirCheck on {}. Found {} dirs, {} dead dirs, {} orphan dirs.", pathToVault, healthyDirs, dirVisitor.dirIds.size(), dirVisitor.secondLevelDirs.size());
		return result;
	}

	private static class DirVisitor extends SimpleFileVisitor<Path> {

		private final Path dataDirPath;
		public final Set<String> dirIds = new HashSet<>(); // contents of all found dir.c9r files
		public final Set<Path> secondLevelDirs = new HashSet<>(); // all d/2/30 dirs

		public DirVisitor(Path dataDirPath) {
			this.dataDirPath = dataDirPath;
			this.dirIds.add(""); // we always have the "empty string" dir id for the root dir
		}

		@Override
		public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) throws IOException {
			if (DIR_FILE_NAME.equals(file.getFileName())) {
				return visitDirFile(file, attrs);
			}
			return FileVisitResult.CONTINUE;
		}

		private FileVisitResult visitDirFile(Path file, BasicFileAttributes attrs) throws IOException {
			assert DIR_FILE_NAME.equals(file.getFileName());
			if (attrs.size() > Constants.MAX_DIR_FILE_LENGTH) { // TODO: add separate dir.c9r plausibility check? or add diagnostic result?
				LOG.warn("Encountered dir.c9r file of size {}", attrs.size());
			} else {
				byte[] bytes = Files.readAllBytes(file);
				String dirId = new String(bytes, StandardCharsets.UTF_8);
				boolean added = dirIds.add(dirId);
				if (!added) {
					// TODO: how to handle this case? add diagnostic result?
					LOG.warn("duplicate dir id");
				}
			}
			return FileVisitResult.SKIP_SIBLINGS;
		}

		@Override
		public FileVisitResult preVisitDirectory(Path dir, BasicFileAttributes attrs) {
			Path relPath = dataDirPath.relativize(dir);
			if (relPath.getNameCount() == 2) {
				secondLevelDirs.add(relPath);
			}
			return FileVisitResult.CONTINUE;
		}
	}

}
