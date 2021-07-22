package org.cryptomator.cryptofs.health.dirid;

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
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.function.Consumer;

/**
 * Reads all dir.c9r files and checks if the corresponding dir exists.
 */
public class DirIdCheck implements HealthCheck {

	private static final Logger LOG = LoggerFactory.getLogger(DirIdCheck.class);
	private static final int MAX_TRAVERSAL_DEPTH = 4; // d/2/30/Fo0==.c9r/dir.c9r
	private static final String CHECK_NAME = "Directory Check";

	@Override
	public String name() {
		return CHECK_NAME;
	}

	@Override
	public void check(Path pathToVault, VaultConfig config, Masterkey masterkey, Cryptor cryptor, Consumer<DiagnosticResult> resultCollector) {
		// scan vault structure:
		var dataDirPath = pathToVault.resolve(Constants.DATA_DIR_NAME);
		var dirVisitor = new DirVisitor(dataDirPath, resultCollector);
		try {
			Files.walkFileTree(dataDirPath, Set.of(), MAX_TRAVERSAL_DEPTH, dirVisitor);
		} catch (IOException e) {
			LOG.error("Traversal of data dir failed.", e);
			resultCollector.accept(new CheckFailed("Traversal of data dir failed. See log for details."));
			return;
		}

		// remove matching pairs:
		var iter = dirVisitor.dirIds.entrySet().iterator();
		while (iter.hasNext()) {
			var entry = iter.next();
			var dirId = entry.getKey();
			var dirIdFile = entry.getValue();
			var hashedDirId = cryptor.fileNameCryptor().hashDirectoryId(dirId);
			var expectedDir = Path.of(hashedDirId.substring(0, 2), hashedDirId.substring(2));
			boolean foundDir = dirVisitor.secondLevelDirs.remove(expectedDir);
			if (foundDir) {
				iter.remove();
				resultCollector.accept(new HealthyDir(dirId, dirIdFile, expectedDir));
			}
		}

		// remaining dirIds (i.e. missing dirs):
		dirVisitor.dirIds.forEach((dirId, dirIdFile) -> {
			resultCollector.accept(new MissingDirectory(dirId, dirIdFile));
		});

		// remaining folders (i.e. missing dir.c9r files):
		dirVisitor.secondLevelDirs.forEach(dir -> {
			resultCollector.accept(new OrphanDir(dir));
		});
	}

	// visible for testing
	static class DirVisitor extends SimpleFileVisitor<Path> {

		private final Path dataDirPath;
		private final Consumer<DiagnosticResult> resultCollector;
		public final Map<String, Path> dirIds = new HashMap<>(); // contents of all found dir.c9r files
		public final Set<Path> secondLevelDirs = new HashSet<>(); // all d/2/30 dirs

		public DirVisitor(Path dataDirPath, Consumer<DiagnosticResult> resultCollector) {
			this.dataDirPath = dataDirPath;
			this.resultCollector = resultCollector;
			this.dirIds.put("", null); // we always have the "empty string" dir id for the root dir
		}

		@Override
		public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) throws IOException {
			if (Constants.DIR_FILE_NAME.equals(file.getFileName().toString())) {
				return visitDirFile(file, attrs);
			}
			return FileVisitResult.CONTINUE;
		}

		private FileVisitResult visitDirFile(Path file, BasicFileAttributes attrs) throws IOException {
			assert Constants.DIR_FILE_NAME.equals(file.getFileName().toString());
			if (attrs.size() > Constants.MAX_DIR_FILE_LENGTH) {
				LOG.warn("Encountered dir.c9r file of size {}", attrs.size());
				resultCollector.accept(new ObeseDirFile(file, attrs.size()));
			} else if (attrs.size() == 0) {
				LOG.warn("Empty dir.c9r file.", file);
				resultCollector.accept(new EmptyDirFile(file));
			} else {
				byte[] bytes = Files.readAllBytes(file);
				String dirId = new String(bytes, StandardCharsets.UTF_8);
				if (dirIds.containsKey(dirId)) {
					var otherFile = dirIds.get(dirId);
					LOG.warn("Same directory ID used by {} and {}", file, otherFile);
					resultCollector.accept(new DirIdCollision(dirId, file, otherFile));
				} else {
					dirIds.put(dirId, file);
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
