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
 * Checks for each c9r or c9s dir in the vault structure if its {@link org.cryptomator.cryptofs.common.CiphertextFileType} can be determined.
 * <p>
 * The type is based on the presence of a signature file.
 * The signature files are {@value org.cryptomator.cryptofs.common.Constants#DIR_FILE_NAME}, {@value org.cryptomator.cryptofs.common.Constants#SYMLINK_FILE_NAME} and {@value org.cryptomator.cryptofs.common.Constants#CONTENTS_FILE_NAME}.
 * Note: For c9r dirs, only the dir and symlink sig files are tested.
 */
public class CiphertextFileTypeCheck implements HealthCheck {

	private static final Logger LOG = LoggerFactory.getLogger(CiphertextFileTypeCheck.class);
	private static final int MAX_TRAVERSAL_DEPTH = 4;

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

	// visible for testing
	static class DirVisitor extends SimpleFileVisitor<Path> {

		private final Consumer<DiagnosticResult> resultCollector;

		public DirVisitor(Consumer<DiagnosticResult> resultCollector) {this.resultCollector = resultCollector;}

		@Override
		public FileVisitResult preVisitDirectory(Path dir, BasicFileAttributes attrs) {
			return switch (determineDirType(dir)) {
				case C9R -> checkCiphertextTypeC9r(dir);
				case C9S -> checkCiphertextTypeC9s(dir);
				case UNKNOWN -> FileVisitResult.CONTINUE;
			};
		}

		DirType determineDirType(Path p) {
			var dirName = p.getFileName().toString();
			if (dirName.endsWith(Constants.CRYPTOMATOR_FILE_SUFFIX)) {
				return DirType.C9R;
			} else if (dirName.endsWith(Constants.DEFLATED_FILE_SUFFIX)) {
				return DirType.C9S;
			} else {
				return DirType.UNKNOWN;
			}
		}

		FileVisitResult checkCiphertextTypeC9r(Path dir) {
			boolean isDir = containsDirFile(dir);
			boolean isSymlink = containsSymlinkFile(dir);

			if (isDir ^ isSymlink) {
				resultCollector.accept(new KnownType(dir));
			} else if (isDir || isSymlink) {
				resultCollector.accept(new AmbiguousType(dir));
			} else {
				resultCollector.accept(new UnknownType(dir));
			}
			return FileVisitResult.SKIP_SUBTREE;
		}

		FileVisitResult checkCiphertextTypeC9s(Path dir) {
			boolean isDir = containsDirFile(dir);
			boolean isSymlink = containsSymlinkFile(dir);
			boolean isFile = containsContentsFile(dir);

			if ((isDir && isFile && isSymlink) ^ isSymlink ^ isFile ^ isDir) {
				resultCollector.accept(new KnownType(dir));
			} else if (isDir || isSymlink || isFile) {
				resultCollector.accept(new AmbiguousType(dir));
			} else {
				resultCollector.accept(new UnknownType(dir));
			}
			return FileVisitResult.SKIP_SUBTREE;
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

	enum DirType {
		C9R,
		C9S,
		UNKNOWN;
	}

}
