package org.cryptomator.cryptofs.common;

import com.google.common.base.Preconditions;
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

	public enum Capability {
		/**
		 * File system allows read access
		 *
		 * @since 1.9.3
		 */
		READ_ACCESS,

		/**
		 * File system allows write access
		 *
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
	 *
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
	 *
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

	/**
	 * Determinse the number of chars a ciphertext filename (including its extension) is allowed to have inside a vault's <code>d/XX/YYYYYYYYYYYYYYYYYYYYYYYYYYYYYY/</code> directory.
	 * 
	 * @param pathToVault Path to the vault
	 * @return Number of chars a .c9r file is allowed to have
	 * @throws IOException If unable to perform this check
	 */
	public int determineSupportedFileNameLength(Path pathToVault) throws IOException {
		int subPathLength = Constants.MAX_ADDITIONAL_PATH_LENGTH - 2; // subtract "c/"
		return determineSupportedFileNameLength(pathToVault.resolve("c"), subPathLength, Constants.MIN_CIPHERTEXT_NAME_LENGTH, Constants.MAX_CIPHERTEXT_NAME_LENGTH);
	}

	/**
	 * Determines the number of chars a filename is allowed to have inside of subdirectories of <code>dir</code> by running an experiment.
	 *
	 * @param dir               Path to a directory where to conduct the experiment (e.g. <code>/path/to/vault/c</code>)
	 * @param subPathLength     Defines the combined number of chars of the subdirectories inside <code>dir</code>, including slashes but excluding the leading slash. Must be a minimum of 6
	 * @param minFileNameLength The minimum filename length to check
	 * @param maxFileNameLength The maximum filename length to check
	 * @return The supported filename length inside a subdirectory of <code>dir</code> with <code>subPathLength</code> chars
	 * @throws IOException If unable to perform this check
	 */
	public int determineSupportedFileNameLength(Path dir, int subPathLength, int minFileNameLength, int maxFileNameLength) throws IOException {
		Preconditions.checkArgument(subPathLength >= 6, "subPathLength must be larger than charcount(a/nnn/)");
		Preconditions.checkArgument(minFileNameLength > 0);
		Preconditions.checkArgument(maxFileNameLength <= 999);

		String fillerName = Strings.repeat("a", subPathLength - 5);
		assert fillerName.length() > 0;
		Path fillerDir = dir.resolve(fillerName);
		try {
			// make sure we can create _and_ see directories inside of checkDir:
			Files.createDirectories(fillerDir.resolve("nnn"));
			if (!canListDir(fillerDir)) {
				throw new IOException("Unable to read dir");
			}
			// perform actual check:
			return determineSupportedFileNameLength(fillerDir, minFileNameLength, maxFileNameLength + 1);
		} finally {
			deleteRecursivelySilently(fillerDir);
		}
	}

	private int determineSupportedFileNameLength(Path p, int lowerBoundIncl, int upperBoundExcl) {
		assert lowerBoundIncl < upperBoundExcl;
		int mid = (lowerBoundIncl + upperBoundExcl) / 2;
		assert mid < upperBoundExcl;
		if (mid == lowerBoundIncl) {
			return mid; // bounds will not shrink any further at this point
		}
		assert lowerBoundIncl < mid;
		if (canHandleFileNameLength(p, mid)) {
			return determineSupportedFileNameLength(p, mid, upperBoundExcl);
		} else {
			return determineSupportedFileNameLength(p, lowerBoundIncl, mid);
		}
	}

	private boolean canHandleFileNameLength(Path parent, int nameLength) {
		Path checkDir = parent.resolve(String.format("%03d", nameLength));
		Path checkFile = checkDir.resolve(Strings.repeat("a", nameLength));
		try {
			Files.createDirectories(checkDir);
			try {
				Files.createFile(checkFile); // will fail early on "sane" operating systems, if there is a limit
			} catch (FileAlreadyExistsException e) {
				// ok
			}
			return canListDir(checkDir); // will fail on Windows, if checkFile's name is too long
		} catch (IOException e) {
			return false;
		} finally {
			deleteSilently(checkFile); // despite not being able to dirlist, we might still be able to delete this
			deleteRecursivelySilently(checkDir); // only works if dirlist works, therefore after deleting checkFile
		}
	}

	private boolean canListDir(Path dir) {
		try (DirectoryStream<Path> ds = Files.newDirectoryStream(dir)) {
			ds.iterator().hasNext(); // throws DirectoryIteratorException on Windows if child path too long
			return true;
		} catch (DirectoryIteratorException | IOException e) {
			return false;
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
