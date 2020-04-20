package org.cryptomator.cryptofs.common;

import com.google.common.base.Joiner;
import com.google.common.base.Strings;
import com.google.common.io.MoreFiles;
import com.google.common.io.RecursiveDeleteOption;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.file.DirectoryStream;
import java.nio.file.FileSystemException;
import java.nio.file.Files;
import java.nio.file.Path;

public class FileSystemCapabilityChecker {

	private static final Logger LOG = LoggerFactory.getLogger(FileSystemCapabilityChecker.class);

	public enum Capability {
		/**
		 * File system allows read access
		 * @since 1.9.3
		 */
		READ_ACCESS,

		/**
		 * File system allows write access
		 * @since 1.9.3
		 */
		WRITE_ACCESS,
		
		/**
		 * File system supports filenames with ≥ 230 chars.
		 * @since @since 1.9.2
		 */
		LONG_FILENAMES,

		/**
		 * File system supports paths with ≥ 300 chars.
		 * @since @since 1.9.2
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
	public void assertAllCapabilities(Path pathToVault) throws MissingCapabilityException {
		assertReadAccess(pathToVault);
		assertWriteAccess(pathToVault);
		assertLongFilenameSupport(pathToVault);
		assertLongFilePathSupport(pathToVault);
	}

	/**
	 * Checks whether the underlying filesystem allows reading the given dir.
	 * @param pathToVault Path to a vault's storage location
	 * @throws MissingCapabilityException if the check fails
	 * @since 1.9.3
	 */
	public void assertReadAccess(Path pathToVault) throws MissingCapabilityException {
		try (DirectoryStream ds = Files.newDirectoryStream(pathToVault)) {
			assert ds != null;
		} catch (IOException e) {
			throw new MissingCapabilityException(pathToVault, Capability.READ_ACCESS);
		}
	}

	/**
	 * Checks whether the underlying filesystem allows writing to the given dir.
	 * @param pathToVault Path to a vault's storage location
	 * @throws MissingCapabilityException if the check fails
	 * @since 1.9.3
	 */
	public void assertWriteAccess(Path pathToVault) throws MissingCapabilityException {
		Path checkDir = pathToVault.resolve("c");
		try {
			Files.createDirectory(checkDir);
		} catch (IOException e) {
			throw new MissingCapabilityException(checkDir, Capability.WRITE_ACCESS);
		} finally {
			deleteSilently(checkDir);
		}
	}

	public void assertLongFilenameSupport(Path pathToVault) throws MissingCapabilityException {
		String longFileName = Strings.repeat("a", 226) + ".c9r";
		Path checkDir = pathToVault.resolve("c");
		Path p = checkDir.resolve(longFileName);
		try {
			Files.createDirectories(p);
		} catch (IOException e) {
			throw new MissingCapabilityException(p, Capability.LONG_FILENAMES);
		} finally {
			deleteSilently(checkDir);
		}
	}

	public void assertLongFilePathSupport(Path pathToVault) throws MissingCapabilityException {
		String longFileName = Strings.repeat("a", 96) + ".c9r";
		String longPath = Joiner.on('/').join(longFileName, longFileName, longFileName);
		Path checkDir = pathToVault.resolve("c");
		Path p = checkDir.resolve(longPath);
		try {
			Files.createDirectories(p);
		} catch (IOException e) {
			throw new MissingCapabilityException(p, Capability.LONG_PATHS);
		} finally {
			deleteSilently(checkDir);
		}
	}

	private void deleteSilently(Path dir) {
		try {
			if (Files.exists(dir)) {
				MoreFiles.deleteRecursively(dir, RecursiveDeleteOption.ALLOW_INSECURE);
			}
		} catch (IOException e) {
			LOG.warn("Failed to clean up " + dir, e);
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
