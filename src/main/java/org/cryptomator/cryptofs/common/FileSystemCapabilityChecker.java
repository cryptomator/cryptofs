package org.cryptomator.cryptofs.common;

import com.google.common.base.Joiner;
import com.google.common.base.Strings;
import com.google.common.io.MoreFiles;
import com.google.common.io.RecursiveDeleteOption;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.file.FileSystemException;
import java.nio.file.Files;
import java.nio.file.Path;

public class FileSystemCapabilityChecker {

	private static final Logger LOG = LoggerFactory.getLogger(FileSystemCapabilityChecker.class);

	public enum Capability {
		/**
		 * File system supports filenames with ≥ 230 chars.
		 */
		LONG_FILENAMES,

		/**
		 * File system supports paths with ≥ 400 chars.
		 */
		LONG_PATHS,
	}

	/**
	 * Checks whether the underlying filesystem has all required capabilities.
	 *
	 * @param pathToVault Path to a vault's storage location
	 * @throws MissingCapabilityException if any check fails
	 * @implNote Only short-running tests with constant time are performed
	 * @since 1.9.2
	 */
	public void checkCapabilities(Path pathToVault) throws MissingCapabilityException {
		Path checkDir = pathToVault.resolve("c");
		try {
			checkLongFilenames(checkDir);
			checkLongFilePaths(checkDir);
		} finally {
			try {
				MoreFiles.deleteRecursively(checkDir, RecursiveDeleteOption.ALLOW_INSECURE);
			} catch (IOException e) {
				LOG.warn("Failed to clean up " + checkDir, e);
			}
		}
	}

	private void checkLongFilenames(Path checkDir) throws MissingCapabilityException {
		String longFileName = Strings.repeat("a", 226) + ".c9r";
		Path p = checkDir.resolve(longFileName);
		try {
			Files.createDirectories(p);
		} catch (IOException e) {
			throw new MissingCapabilityException(p, Capability.LONG_FILENAMES);
		}
	}

	private void checkLongFilePaths(Path checkDir) throws MissingCapabilityException {
		String longFileName = Strings.repeat("a", 96) + ".c9r";
		String longPath = Joiner.on('/').join(longFileName, longFileName, longFileName, longFileName);
		Path p = checkDir.resolve(longPath);
		try {
			Files.createDirectories(p);
		} catch (IOException e) {
			throw new MissingCapabilityException(p, Capability.LONG_PATHS);
		}
	}

	public static class MissingCapabilityException extends FileSystemException {

		private final Capability missingCapability;

		public MissingCapabilityException(Path path, Capability missingCapability) {
			super(path.toString(), null, "Filesystem doesn't support " + missingCapability);
			this.missingCapability = missingCapability;
		}

		public Capability getMissingCapability() {
			return missingCapability;
		}
	}

}
