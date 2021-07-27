package org.cryptomator.cryptofs.health.type;

import org.cryptomator.cryptofs.VaultConfig;
import org.cryptomator.cryptofs.common.CiphertextFileType;
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
import java.util.EnumSet;
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
	private static final int MAX_TRAVERSAL_DEPTH = 3;

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
		public FileVisitResult visitFile(Path dir, BasicFileAttributes attrs) {
			switch (determineFileType(dir, attrs)) {
				case C9R_DIR -> checkCiphertextTypeC9r(dir);
				case C9S_DIR -> checkCiphertextTypeC9s(dir);
				case UNRELATED -> {}
			}
			;
			return FileVisitResult.CONTINUE;
		}

		DirType determineFileType(Path p, BasicFileAttributes attrs) {
			var dirName = p.getFileName().toString();
			boolean isDir = attrs.isDirectory();

			if (isDir && dirName.endsWith(Constants.CRYPTOMATOR_FILE_SUFFIX)) {
				return DirType.C9R_DIR;
			} else if (isDir && dirName.endsWith(Constants.DEFLATED_FILE_SUFFIX)) {
				return DirType.C9S_DIR;
			} else {
				return DirType.UNRELATED;
			}
		}

		void checkCiphertextTypeC9r(Path dir) {
			boolean isDir = containsDirFile(dir);
			boolean isSymlink = containsSymlinkFile(dir);
			var types = ciphertextFileTypesFrom(isDir, isSymlink, false);

			if (isDir ^ isSymlink) {
				resultCollector.accept(new KnownType(dir, types.iterator().next()));
			} else if (isDir || isSymlink) {
				resultCollector.accept(new AmbiguousType(dir, types));
			} else {
				resultCollector.accept(new UnknownType(dir));
			}
		}

		void checkCiphertextTypeC9s(Path dir) {
			boolean isDir = containsDirFile(dir);
			boolean isSymlink = containsSymlinkFile(dir);
			boolean isFile = containsContentsFile(dir);
			var types = ciphertextFileTypesFrom(isDir, isSymlink, isFile);

			if ((isDir && isFile && isSymlink) ^ isSymlink ^ isFile ^ isDir) {
				resultCollector.accept(new KnownType(dir, types.iterator().next()));
			} else if (isDir || isSymlink || isFile) {
				resultCollector.accept(new AmbiguousType(dir, types));
			} else {
				resultCollector.accept(new UnknownType(dir));
			}
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

		private Set<CiphertextFileType> ciphertextFileTypesFrom(boolean isDir, boolean isSymlink, boolean isFile) {
			if (isDir && isSymlink && isFile) {
				return EnumSet.of(CiphertextFileType.DIRECTORY, CiphertextFileType.SYMLINK, CiphertextFileType.FILE);
			} else if (isDir && isSymlink) {
				return EnumSet.of(CiphertextFileType.DIRECTORY, CiphertextFileType.SYMLINK);
			} else if (isDir && isFile) {
				return EnumSet.of(CiphertextFileType.DIRECTORY, CiphertextFileType.FILE);
			} else if (isSymlink && isFile) {
				return EnumSet.of(CiphertextFileType.SYMLINK, CiphertextFileType.FILE);
			} else if (isDir) {
				return EnumSet.of(CiphertextFileType.DIRECTORY);
			} else if (isSymlink) {
				return EnumSet.of(CiphertextFileType.SYMLINK);
			} else if (isFile) {
				return EnumSet.of(CiphertextFileType.SYMLINK);
			} else {
				return EnumSet.noneOf(CiphertextFileType.class);
			}
		}

	}

	enum DirType {
		C9R_DIR,
		C9S_DIR,
		UNRELATED;
	}

}
