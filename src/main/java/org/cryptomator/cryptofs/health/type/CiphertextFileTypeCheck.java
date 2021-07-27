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

	//octal representation of present signature files
	private static final int FILE = 1;
	private static final int LINK = 2;
	private static final int DIR = 4;

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
				case C9R_DIR -> checkCiphertextType(dir, false);
				case C9S_DIR -> checkCiphertextType(dir, true);
				case UNRELATED -> {}
			}
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

		void checkCiphertextType(Path dir, boolean checkForContentsC9r) {
			int octalTypes = (containsDirFile(dir) ? DIR : 0) //
					+ (containsSymlinkFile(dir) ? LINK : 0) //
					+ (checkForContentsC9r && containsContentsFile(dir) ? FILE : 0);
			var types = ciphertextFileTypesFromOctal(octalTypes);
			resultCollector.accept(switch (types.size()) {
				case 0 -> new UnknownType(dir);
				case 1 -> new KnownType(dir, types.iterator().next());
				default -> new AmbiguousType(dir, types);
			});
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

		private Set<CiphertextFileType> ciphertextFileTypesFromOctal(int octalTypes) {
			return switch (octalTypes) {
				case 0 -> EnumSet.noneOf(CiphertextFileType.class);
				case 1 -> EnumSet.of(CiphertextFileType.FILE);
				case 2 -> EnumSet.of(CiphertextFileType.SYMLINK);
				case 3 -> EnumSet.of(CiphertextFileType.SYMLINK, CiphertextFileType.FILE);
				case 4 -> EnumSet.of(CiphertextFileType.DIRECTORY);
				case 5 -> EnumSet.of(CiphertextFileType.DIRECTORY, CiphertextFileType.FILE);
				case 6 -> EnumSet.of(CiphertextFileType.DIRECTORY, CiphertextFileType.SYMLINK);
				case 7 -> EnumSet.of(CiphertextFileType.DIRECTORY, CiphertextFileType.SYMLINK, CiphertextFileType.FILE);
				default -> throw new IllegalArgumentException("octalTypes must be a number between 0 and 7");
			};
		}

	}

	enum DirType {
		C9R_DIR,
		C9S_DIR,
		UNRELATED;
	}

}
