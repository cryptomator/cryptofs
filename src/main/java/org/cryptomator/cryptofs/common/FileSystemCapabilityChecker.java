package org.cryptomator.cryptofs.common;

import com.google.common.base.Strings;
import com.google.common.io.MoreFiles;
import com.google.common.io.RecursiveDeleteOption;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.file.DirectoryIteratorException;
import java.nio.file.DirectoryStream;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.FileSystemException;
import java.nio.file.Files;
import java.nio.file.Path;

public class FileSystemCapabilityChecker {

	private static final Logger LOG = LoggerFactory.getLogger(FileSystemCapabilityChecker.class);
	private static final int MAX_PATH_LEN_REQUIRED = 268; // see math at https://github.com/cryptomator/cryptofs/issues/77
	private static final int MIN_PATH_LEN_REQUIRED = 64;
	private static final String TMP_FS_CHECK_DIR = "temporary-filesystem-capability-check-dir"; // must have 41 chars!

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
			Files.createDirectories(checkDir);
			Path tmpDir = Files.createTempDirectory(checkDir, "write-access");
			Files.delete(tmpDir);
		} catch (IOException e) {
			throw new MissingCapabilityException(checkDir, Capability.WRITE_ACCESS);
		} finally {
			deleteRecursivelySilently(checkDir);
		}
	}
	
	public int determineSupportedPathLength(Path pathToVault) {
		if (canHandlePathLength(pathToVault, MAX_PATH_LEN_REQUIRED)) {
			return MAX_PATH_LEN_REQUIRED;
		} else {
			return determineSupportedPathLength(pathToVault, MIN_PATH_LEN_REQUIRED, MAX_PATH_LEN_REQUIRED);
		}
	}
	
	private int determineSupportedPathLength(Path pathToVault, int lowerBound, int upperBound) {
		assert lowerBound <= upperBound;
		int mid = (lowerBound + upperBound) / 2;
		if (mid == lowerBound) {
			return mid; // bounds will not shrink any further at this point
		}
		if (canHandlePathLength(pathToVault, mid)) {
			return determineSupportedPathLength(pathToVault, mid, upperBound);
		} else {
			return determineSupportedPathLength(pathToVault, lowerBound, mid);
		}
	}
	
	private boolean canHandlePathLength(Path pathToVault, int pathLength) {
		assert pathLength > 48;
		String checkDirStr = "c/" + TMP_FS_CHECK_DIR + String.format("/%03d/", pathLength);
		assert checkDirStr.length() == 48; // 268 - 220
		int filenameLength = pathLength - checkDirStr.length();
		Path checkDir = pathToVault.resolve(checkDirStr);
		Path checkFile = checkDir.resolve(Strings.repeat("a", filenameLength));
		try {
			Files.createDirectories(checkDir);
			try {
				Files.createFile(checkFile); // will fail early on "sane" operating systems, if there is a limit
			} catch (FileAlreadyExistsException e) {
				// ok
			}
			try (DirectoryStream<Path> ds = Files.newDirectoryStream(checkDir)) {
				ds.iterator().hasNext(); // will fail with DirectoryIteratorException on Windows if path of children too long
				return true;
			}
		} catch (DirectoryIteratorException | IOException e) {
			return false;
		} finally {
			deleteSilently(checkFile); // despite not being able to dirlist, we might still be able to delete this
			deleteRecursivelySilently(checkDir); // only works if dirlist works, therefore after deleting checkFile
		}
	}
	
	private void deleteSilently(Path path) {
		try {
			Files.delete(path);
		} catch (IOException e) {
			LOG.trace("Failed to delete " + path, e);
		}
	}

	private void deleteRecursivelySilently(Path dir) {
		try {
			if (Files.exists(dir)) {
				MoreFiles.deleteRecursively(dir, RecursiveDeleteOption.ALLOW_INSECURE);
			}
		} catch (IOException e) {
			LOG.trace("Failed to clean up " + dir, e);
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
