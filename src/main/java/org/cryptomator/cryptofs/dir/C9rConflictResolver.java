package org.cryptomator.cryptofs.dir;

import static org.cryptomator.cryptofs.common.Constants.DIR_FILE_NAME;
import static org.cryptomator.cryptofs.common.Constants.SYMLINK_FILE_NAME;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.ReadableByteChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.util.function.Consumer;
import java.util.stream.Stream;

import org.cryptomator.cryptofs.VaultConfig;
import org.cryptomator.cryptofs.common.Constants;
import org.cryptomator.cryptofs.event.ConflictResolutionFailedEvent;
import org.cryptomator.cryptofs.event.ConflictResolvedEvent;
import org.cryptomator.cryptofs.event.FilesystemEvent;
import org.cryptomator.cryptolib.api.Cryptor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.base.Preconditions;
import com.google.common.io.BaseEncoding;
import com.google.common.io.MoreFiles;
import com.google.common.io.RecursiveDeleteOption;

import jakarta.inject.Inject;
import jakarta.inject.Named;

@DirectoryStreamScoped
class C9rConflictResolver {

	private static final Logger LOG = LoggerFactory.getLogger(C9rConflictResolver.class);

	private final Cryptor cryptor;
	private final byte[] dirId;
	private final int maxC9rFileNameLength;
	private final Path cleartextPath;
	private final int maxCleartextFileNameLength;
	private final Consumer<FilesystemEvent> eventConsumer;

	@Inject
	public C9rConflictResolver(Cryptor cryptor, @Named("dirId") String dirId, VaultConfig vaultConfig, Consumer<FilesystemEvent> eventConsumer, @Named("cleartextPath") Path cleartextPath) {
		this.cryptor = cryptor;
		this.dirId = dirId.getBytes(StandardCharsets.US_ASCII);
		this.maxC9rFileNameLength = vaultConfig.getShorteningThreshold();
		this.cleartextPath = cleartextPath;
		this.maxCleartextFileNameLength = (maxC9rFileNameLength - 4) / 4 * 3 - 16; // math from FileSystemCapabilityChecker.determineSupportedCleartextFileNameLength()
		this.eventConsumer = eventConsumer;
	}

	public Stream<Node> process(Node node) {
		Preconditions.checkArgument(node.extractedCiphertext != null, "Can only resolve conflicts if extractedCiphertext is set");
		Preconditions.checkArgument(node.cleartextName != null, "Can only resolve conflicts if cleartextName is set");

		String canonicalCiphertextFileName = node.extractedCiphertext + Constants.CRYPTOMATOR_FILE_SUFFIX;
		if (node.fullCiphertextFileName.equals(canonicalCiphertextFileName)) {
			// not a conflict:
			return Stream.of(node);
		} else if (node.fullCiphertextFileName.startsWith(".")) {
			// ignore hidden files:
			LOG.debug("Ignoring hidden file {}", node.ciphertextPath);
			return Stream.empty();
		} else {
			// conflicting file:
			try {
				Path canonicalPath = node.ciphertextPath.resolveSibling(canonicalCiphertextFileName);
				return resolveConflict(node, canonicalPath);
			} catch (IOException e) {
				eventConsumer.accept(new ConflictResolutionFailedEvent(cleartextPath.resolve(node.cleartextName), node.ciphertextPath, e));
				LOG.warn("Failed to resolve conflict for {}", node.ciphertextPath, e);
				return Stream.empty();
			}
		}
	}

	//visible for testing
	Stream<Node> resolveConflict(Node conflicting, Path canonicalPath) throws IOException {
		Path conflictingPath = conflicting.ciphertextPath;
		return switch (resolveConflictTrivially(canonicalPath, conflictingPath)) {
			case RESOLVED -> {
				Node resolved = new Node(canonicalPath);
				resolved.cleartextName = conflicting.cleartextName;
				resolved.extractedCiphertext = conflicting.extractedCiphertext;
				yield Stream.of(resolved);
			}
			case SKIP -> {
				// renaming is irreversible: as soon as a directory is renamed, its new name is canonical.#
				// If we can't tell whether both are copies of the very same, we skip and retry on next listing.
				LOG.info("Postponing conflict resolution for {}: Not all required files exist (yet).", conflictingPath);
				yield Stream.<Node>empty();
			}
			case UNRESOLVED -> {
				yield renameConflictingFile(canonicalPath, conflicting);
			}
		};
	}

	/**
	 * Resolves a conflict by renaming the conflicting file.
	 *
	 * @param canonicalPath The path to the original (conflict-free) file.
	 * @param conflicting The conflicting file.
	 * @return The newly created Node if rename succeeded or an empty stream otherwise.
	 * @throws IOException If an unexpected I/O exception occurs during rename
	 */
	private Stream<Node> renameConflictingFile(Path canonicalPath, Node conflicting) throws IOException {
		assert Files.exists(canonicalPath);
		assert conflicting.fullCiphertextFileName.endsWith(Constants.CRYPTOMATOR_FILE_SUFFIX);
		assert conflicting.fullCiphertextFileName.contains(conflicting.extractedCiphertext);

		final String cleartext = conflicting.cleartextName;
		final int beginOfCleartextExt = cleartext.lastIndexOf('.');
		final String cleartextFileExt = (beginOfCleartextExt > 0) ? cleartext.substring(beginOfCleartextExt) : "";
		final String cleartextBasename = (beginOfCleartextExt > 0) ? cleartext.substring(0, beginOfCleartextExt) : cleartext;

		// let's assume that some the sync conflict string is added at the end of the file name, but before .c9r:
		final int endOfCiphertext = conflicting.fullCiphertextFileName.indexOf(conflicting.extractedCiphertext) + conflicting.extractedCiphertext.length();
		final String originalConflictSuffix = conflicting.fullCiphertextFileName.substring(endOfCiphertext, conflicting.fullCiphertextFileName.length() - Constants.CRYPTOMATOR_FILE_SUFFIX.length());

		// split available maxCleartextFileNameLength between basename, conflict suffix, and file extension:
		final int netCleartext = maxCleartextFileNameLength - cleartextFileExt.length(); // file extension must be preserved
		final String conflictSuffix = originalConflictSuffix.substring(0, Math.min(originalConflictSuffix.length(), netCleartext / 2)); // max 50% of available space
		final int conflictSuffixLen = Math.max(4, conflictSuffix.length()); // prefer to use original conflict suffix, but reserver at least 4 chars for numerical fallback: " (9)"
		final String lengthRestrictedBasename = cleartextBasename.substring(0, Math.min(cleartextBasename.length(), netCleartext - conflictSuffixLen)); // remaining space for basename

		// attempt to use original conflict suffix:
		String alternativeCleartext = lengthRestrictedBasename + conflictSuffix + cleartextFileExt;
		String alternativeCiphertext = cryptor.fileNameCryptor().encryptFilename(BaseEncoding.base64Url(), alternativeCleartext, dirId);
		String alternativeCiphertextName = alternativeCiphertext + Constants.CRYPTOMATOR_FILE_SUFFIX;
		Path alternativePath = canonicalPath.resolveSibling(alternativeCiphertextName);

		// fallback to number conflic suffix, if file with alternative path already exists:
		for (int i = 1; i < 10 && Files.exists(alternativePath); i++) {
			alternativeCleartext = lengthRestrictedBasename + " (" + i + ")" + cleartextFileExt;
			alternativeCiphertext = cryptor.fileNameCryptor().encryptFilename(BaseEncoding.base64Url(), alternativeCleartext, dirId);
			alternativeCiphertextName = alternativeCiphertext + Constants.CRYPTOMATOR_FILE_SUFFIX;
			alternativePath = canonicalPath.resolveSibling(alternativeCiphertextName);
		}

		assert alternativeCiphertextName.length() <= maxC9rFileNameLength;
		if (Files.exists(alternativePath)) {
			LOG.warn("Failed finding alternative name for {}: Alternative name {} already exists. Keeping original name.", conflicting.ciphertextPath, alternativePath);
			return Stream.empty();
		}

		Files.move(conflicting.ciphertextPath, alternativePath, StandardCopyOption.ATOMIC_MOVE);
		LOG.info("Renamed conflicting file {} to {}...", conflicting.ciphertextPath, alternativePath);
		Node node = new Node(alternativePath);
		node.cleartextName = alternativeCleartext;
		node.extractedCiphertext = alternativeCiphertext;
		eventConsumer.accept(new ConflictResolvedEvent(cleartextPath.resolve(cleartext), conflicting.ciphertextPath, cleartextPath.resolve(alternativeCleartext), alternativePath));
		return Stream.of(node);
	}


	/**
	 * Tries to resolve a conflict either by moving the conflicting part to the
	 * canonical path (if that is still vacant) or by deleting it (i.e. copy of the canonical
	 * resource). In both cases only the canonical path will exist afterwards.
	 * <p>
	 * Resolution is postponed if the type of either .c9r directory cannot be determined, i.e. if it contains neither a
	 * non-empty {@value Constants#DIR_FILE_NAME} nor a non-empty {@value Constants#SYMLINK_FILE_NAME}.
	 *
	 * @param canonicalPath The path to the original (conflict-free) resource.
	 * @param conflictingPath The path to the potentially conflicting resource (known to exist).
	 * @return {@link TrivialResult#RESOLVED} if only the canonical path remains, {@link TrivialResult#UNRESOLVED} if
	 *         the conflicting resource needs to be renamed, or {@link TrivialResult#SKIP} if the decision must be
	 *         deferred to a later directory listing.
	 * @throws IOException If an I/O exception occurs while moving, reading or deleting either resource.
	 */
	private TrivialResult resolveConflictTrivially(Path canonicalPath, Path conflictingPath) throws IOException {
		try {
			Files.move(conflictingPath, canonicalPath);
			return TrivialResult.RESOLVED; //boom. conflict solved.
		} catch(FileAlreadyExistsException e) {
			//okay, let's try something else
		}

		if (!Files.isDirectory(conflictingPath) || !Files.isDirectory(canonicalPath)) {
			return TrivialResult.UNRESOLVED; //if one of the paths is a file, rename is mandatory
		}

		//try dir resolution
		var dirComparison = compareTypeFile(conflictingPath, canonicalPath, DIR_FILE_NAME, Constants.MAX_DIR_ID_LENGTH, true);
		if (dirComparison.bothAreComparable()) {
			if(dirComparison.sameContent()) {
				removeConflictingDir(conflictingPath, canonicalPath);
				return TrivialResult.RESOLVED;
			} else {
				return TrivialResult.UNRESOLVED;
			}
		}

		//try symlink resolution. link targets vary in length, so any non-empty content is comparable
		var symlinkComparison = compareTypeFile(conflictingPath, canonicalPath, SYMLINK_FILE_NAME, Constants.MAX_SYMLINK_LENGTH, false);
		if (symlinkComparison.bothAreComparable()) {
			if(symlinkComparison.sameContent()) {
				removeConflictingDir(conflictingPath, canonicalPath);
				return TrivialResult.RESOLVED;
			} else {
				return TrivialResult.UNRESOLVED;
			}
		}

		// no type file could be compared: only postpone if the type of one of the dirs is undeterminable.
		// if both types are known, they simply differ (e.g. dir vs symlink) and must be renamed apart.
		var conflictingTypeKnown = dirComparison.isConflictingComparable() || symlinkComparison.isConflictingComparable();
		var canonicalTypeKnown = dirComparison.isCanonicalTypeComparable() || symlinkComparison.isCanonicalTypeComparable();
		if (conflictingTypeKnown && canonicalTypeKnown) {
			return TrivialResult.UNRESOLVED;
		} else {
			return TrivialResult.SKIP;
		}
	}

	private void removeConflictingDir(Path conflictingPath, Path canonicalPath) throws IOException {
		LOG.info("Removing conflicting directory {} (identical to {})", conflictingPath, canonicalPath);
		try {
			MoreFiles.deleteRecursively(conflictingPath, RecursiveDeleteOption.ALLOW_INSECURE);
		} catch(NoSuchFileException _ ) {
			//ok
		}
	}

	/**
	 * Reads and compares the given type file of two conflicting .c9r directories. Presence, emptiness and content of
	 * each type file are derived from one and the same read, so that no state drift can occur between observing
	 * <em>whether</em> a directory is of this type and <em>which</em> resource it points to.
	 *
	 * @param conflictingPath The path to the potentially conflicting .c9r directory.
	 * @param canonicalPath The path to the canonical .c9r directory.
	 * @param typeFileName Name of the type file to compare, e.g. {@value Constants#DIR_FILE_NAME}.
	 * @param numBytesToCompare Number of bytes to read from each type file and compare to each other.
	 * @param requireFullLength Whether this kind of type file has a fixed length of <code>numBytesToCompare</code>, so
	 *                          that anything shorter must be a partial write rather than a shorter value.
	 * @return The result of the comparison.
	 * @throws IOException If an I/O exception occurs while reading either type file.
	 */
	private TypeFileComparison compareTypeFile(Path conflictingPath, Path canonicalPath, String typeFileName, int numBytesToCompare, boolean requireFullLength) throws IOException {
		var conflictingContent = readUpTo(conflictingPath.resolve(typeFileName), numBytesToCompare);
		var canonicalContent = readUpTo(canonicalPath.resolve(typeFileName), numBytesToCompare);
		var minLength = requireFullLength ? numBytesToCompare : 1;
		var isConflictingComparable = conflictingContent.remaining() >= minLength; //there is enough content inside!
		var isCanonicalTypeComparable = canonicalContent.remaining() >= minLength;
		return new TypeFileComparison(isConflictingComparable, isCanonicalTypeComparable, //
				isConflictingComparable && isCanonicalTypeComparable && conflictingContent.equals(canonicalContent));
	}

	/**
	 * The result of comparing one kind of type file (e.g. {@value Constants#DIR_FILE_NAME}) of two conflicting .c9r
	 * directories. A type file that is missing, empty or shorter than expected does not allow a comparsion: either the
	 * directory is not of this type at all ({@value Constants#DIR_FILE_NAME} vs {@value Constants#SYMLINK_FILE_NAME}), or it is in a transient state.
	 *
	 * @param isConflictingComparable Whether the conflicting directory contains a sufficiently long type file of this kind.
	 * @param isCanonicalTypeComparable Whether the canonical directory contains a sufficiently long type file of this kind.
	 * @param sameContent Whether both directories are of this type and their type files have equal content.
	 */
	private record TypeFileComparison(boolean isConflictingComparable, boolean isCanonicalTypeComparable, boolean sameContent) {

		/**
		 * @return <code>true</code> if both directories are of this type, i.e. their type files are comparable.
		 */
		boolean bothAreComparable() {
			return isConflictingComparable && isCanonicalTypeComparable;
		}
	}

	enum TrivialResult {
		RESOLVED,
		UNRESOLVED,
		SKIP;
	}

	/**
	 * Reads up to <code>numBytes</code> bytes from the given file. A file that does not exist is indistinguishable
	 * from an empty one: both yield an empty buffer, since neither tells us anything about its parent's type.
	 *
	 * @param path The file to read from
	 * @param numBytes Maximum number of bytes to read
	 * @return A buffer containing the bytes read, ready to be consumed. Empty if the file is empty or absent.
	 * @throws IOException If an I/O exception occurs while reading.
	 */
	private ByteBuffer readUpTo(Path path, int numBytes) throws IOException {
		try (var channel = Files.newByteChannel(path, StandardOpenOption.READ)) {
			return readUpTo(channel, numBytes);
		} catch (NoSuchFileException e) {
			return ByteBuffer.allocate(0);
		}
	}

	/**
	 * Reads up to <code>numBytes</code> bytes from the given channel.
	 *
	 * @param channel The channel to read from
	 * @param numBytes Maximum number of bytes to read
	 * @return A buffer containing the bytes read, ready to be consumed.
	 * @throws IOException If an I/O exception occurs while reading.
	 */
	private ByteBuffer readUpTo(ReadableByteChannel channel, int numBytes) throws IOException {
		var buffer = ByteBuffer.allocate(numBytes);
		var attempts = 10;
		int i = 0;
		while (buffer.hasRemaining() && channel.read(buffer) != -1 && i < attempts) {
			// read until (buffer is full || EOF is reached || too many attempts)
			i++;
		}
		return buffer.flip();
	}
}
