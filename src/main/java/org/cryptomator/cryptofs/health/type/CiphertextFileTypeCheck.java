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
 * The type is based on the presence of a valid type file.
 * Valid type files for a c9r dir are {@value org.cryptomator.cryptofs.common.Constants#DIR_FILE_NAME} and {@value org.cryptomator.cryptofs.common.Constants#SYMLINK_FILE_NAME}.
 * Valid type files for a c9s dir are the ones for c9r and {@value org.cryptomator.cryptofs.common.Constants#CONTENTS_FILE_NAME}.
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
		}
	}

	// visible for testing
	static class DirVisitor extends SimpleFileVisitor<Path> {

		private final Consumer<DiagnosticResult> resultCollector;

		public DirVisitor(Consumer<DiagnosticResult> resultCollector) {
			this.resultCollector = resultCollector;
		}

		@Override
		public FileVisitResult visitFile(Path dir, BasicFileAttributes attrs) {
			var name = dir.getFileName().toString();
			if (attrs.isDirectory() && name.endsWith(Constants.CRYPTOMATOR_FILE_SUFFIX)) {
				checkCiphertextType(dir, false);
			} else if (attrs.isDirectory() && name.endsWith(Constants.DEFLATED_FILE_SUFFIX)) {
				checkCiphertextType(dir, true);
			}
			return FileVisitResult.CONTINUE;
		}

		// visible for testing
		void checkCiphertextType(Path dir, boolean checkForContentsC9r) {
			var types = containedCiphertextFileTypes(dir, checkForContentsC9r);
			resultCollector.accept(switch (types.size()) {
				case 0 -> new UnknownType(dir);
				case 1 -> new KnownType(dir, types.iterator().next());
				default -> new AmbiguousType(dir, types);
			});
		}

		private Set<CiphertextFileType> containedCiphertextFileTypes(Path dir, boolean checkForContentsC9r) {
			var result = EnumSet.noneOf(CiphertextFileType.class);
			if (containsDirFile(dir)) {
				result.add(CiphertextFileType.DIRECTORY);
			}
			if (containsSymlinkFile(dir)) {
				result.add(CiphertextFileType.SYMLINK);
			}
			if (checkForContentsC9r && containsContentsFile(dir)) {
				result.add(CiphertextFileType.FILE);
			}
			return result;
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
