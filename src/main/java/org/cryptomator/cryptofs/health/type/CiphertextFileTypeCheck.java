package org.cryptomator.cryptofs.health.type;

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
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.Set;
import java.util.function.Consumer;

/**
 * TODO: doc, doc, doc
 */
public class CiphertextFileTypeCheck implements HealthCheck {

	private static final Logger LOG = LoggerFactory.getLogger(CiphertextFileTypeCheck.class);
	private static final int MAX_TRAVERSAL_DEPTH = 4; //TODO: correct?

	@Override
	public String name() {
		return "Resource Type Check";
	}

	@Override
	public void check(Path pathToVault, VaultConfig config, Masterkey masterkey, Cryptor cryptor, Consumer<DiagnosticResult> resultCollector) {

		// scan vault structure:
		var dataDirPath = pathToVault.resolve(Constants.DATA_DIR_NAME);
		var dirVisitor = new CiphertextFileTypeCheck.DirVisitor(resultCollector);
		try {
			Files.walkFileTree(dataDirPath, Set.of(), MAX_TRAVERSAL_DEPTH, dirVisitor);
		} catch (IOException e) {
			LOG.error("Traversal of data dir failed.", e);
			resultCollector.accept(new CheckFailed("Traversal of data dir failed. See log for details."));
			return;
		}
	}

	private class DirVisitor extends SimpleFileVisitor<Path> {

		private final Consumer<DiagnosticResult> resultCollector;

		public DirVisitor(Consumer<DiagnosticResult> resultCollector) {this.resultCollector = resultCollector;}

		@Override
		public FileVisitResult preVisitDirectory(Path dir, BasicFileAttributes attrs) {
			var dirName = dir.getFileName().toString();
			if (dirName.endsWith(Constants.CRYPTOMATOR_FILE_SUFFIX) || dirName.endsWith(Constants.DEFLATED_FILE_SUFFIX)) {
				if (isValidFileType(dir)) {
					resultCollector.accept(new KnownType(dir));
				} else {
					resultCollector.accept(new UnknownType(dir));
				}
				return FileVisitResult.SKIP_SUBTREE;
			} else {
				return FileVisitResult.CONTINUE;
			}
		}

		private boolean isValidFileType(Path p) {
			return containsDirFile(p) //
					|| containsSymlinkFile(p) //
					|| containsContentsFile(p);
		}

		private boolean containsDirFile(Path path) {
			var dirc9r = path.resolve(Constants.DIR_FILE_NAME);
			return Files.isRegularFile(dirc9r, LinkOption.NOFOLLOW_LINKS);
		}

		private boolean containsSymlinkFile(Path path) {
			var symlinkc9r = path.resolve(Constants.SYMLINK_FILE_NAME);
			return Files.isRegularFile(symlinkc9r, LinkOption.NOFOLLOW_LINKS);
		}

		private boolean containsContentsFile(Path path) {
			var contentsc9r = path.resolve(Constants.CONTENTS_FILE_NAME);
			return Files.isRegularFile(contentsc9r, LinkOption.NOFOLLOW_LINKS);
		}

	}

}
