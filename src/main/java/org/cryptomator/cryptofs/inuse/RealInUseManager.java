package org.cryptomator.cryptofs.inuse;

import org.cryptomator.cryptofs.common.Constants;
import org.cryptomator.cryptofs.common.FileTooBigException;
import org.cryptomator.cryptofs.common.FileUtil;
import org.cryptomator.cryptofs.fh.FileAlreadyInUseException;
import org.jspecify.annotations.NonNull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.util.Properties;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * Management object for the in-use-state of encrypted files.
 * <p>
 * You can just check, if a file is in use with {@link #isInUseByOthers(Path)} or try to mark a file as in-use by this crypto filesystem with {@link #use(Path)}
 * <p>
 * The persistence file of a token has the {@value Constants#INUSE_FILE_SUFFIX} file extension.
 */
public class RealInUseManager implements InUseManager {

	private static final Logger LOG = LoggerFactory.getLogger(RealInUseManager.class);

	private final ConcurrentMap<Path, RealUseToken> useTokens = new ConcurrentHashMap<>();
	private final String owner;

	public RealInUseManager(@NonNull String owner) {
		this.owner = owner;
	}


	@Override
	public boolean isInUseByOthers(Path ciphertextPath) {
		if(useTokens.containsKey(ciphertextPath)) {
			return false;
		}

		try {
			var inUseFilePath = computeInUseFilePath(ciphertextPath);
			return isInUseInternal(inUseFilePath);
		} catch (IllegalArgumentException | IOException e) {
			return false;
		}
	}

	/**
	 * Reads the in-use-file at the given path, validates it and checks if this in-use-file belongs to the running crypto filesystem.
	 *
	 * @param inUseFilePath
	 * @return {@code true} if the in-use-file exists, but owned by different user
	 * @throws IOException if the in-use-file does not exist or cannot be read
	 * @throws IllegalArgumentException if the in-use-file is invalid
	 */
	boolean isInUseInternal(Path inUseFilePath) throws IOException, IllegalArgumentException {
		Properties content = readInUseFile(inUseFilePath);
		if (!content.get("owner").equals(owner)) {
			//TODO: check also timestamps
			return true;
		}
		return false;
	}

	Properties readInUseFile(Path inUseFilePath) throws IOException, IllegalArgumentException {
		//TODO: decryption
		var bytes = FileUtil.readAllBytesSizeRestricted(inUseFilePath, 4_000);
		//TODO: convert to JSON an extract info
		//	for now we use properties
		var props = new Properties();
		try (var stream = new ByteArrayInputStream(bytes)) {
			props.load(stream);
			validate(props);
			return props;
		}
	}

	private void validate(Properties content) throws IllegalArgumentException {
		if (!content.containsKey("owner")) {
			throw new IllegalArgumentException("Invalid in-use-file. Missing key \"owner\"");
		}
		//TODO: more keys
	}

	@Override
	public UseToken use(Path ciphertextPath) throws FileAlreadyInUseException {
		var inUseFilePath = computeInUseFilePath(ciphertextPath);
		try {
			return useTokens.computeIfAbsent(inUseFilePath, this::createInternal);
		} catch (UncheckedIOException e) {
			if (e.getCause() instanceof FileAlreadyInUseException inUseExc) {
				throw inUseExc;
			}

			throw new IllegalStateException("Expected %s, but got:".formatted(FileAlreadyInUseException.class.getSimpleName()), e);
		}
	}

	RealUseToken createInternal(Path inUseFilePath) throws UncheckedIOException {
		try {
			if (isInUseInternal(inUseFilePath)) { //TODO: return also filechannel
				throw new FileAlreadyInUseException(inUseFilePath);
			}
			return RealUseToken.createWithExistingFile(inUseFilePath, owner, useTokens);
		} catch (FileAlreadyInUseException e) {
			throw new UncheckedIOException(e); //wrapped due to Map::compute method
		} catch (NoSuchFileException e) {
			LOG.debug("No in-use-file {} found. Creating it.", inUseFilePath, e);
			return RealUseToken.createWithNewFile(inUseFilePath, owner, useTokens);
		} catch (FileTooBigException | IllegalArgumentException e) {
			LOG.info("Found invalid in-use-file {}. Owning it.", inUseFilePath, e);
			return RealUseToken.createWithExistingInvalidFile(inUseFilePath, owner, useTokens);
		} catch (IOException e) { //TODO: check if we need to pt the token into the map
			LOG.warn("Failed to read in-use file {}. Ignoring it.", inUseFilePath, e);
			return RealUseToken.createInvalid(inUseFilePath, useTokens);
		}
	}

	/**
	 * @param p a path with a filename ending with {@value Constants#CRYPTOMATOR_FILE_SUFFIX}
	 * @return a sibling path with the file extension {@value Constants#INUSE_FILE_SUFFIX}
	 */
	static Path computeInUseFilePath(Path p) {
		var tmp = p.getFileName().toString();
		var fileName = tmp.substring(0, tmp.length() - Constants.CRYPTOMATOR_FILE_SUFFIX.length());
		return p.resolveSibling(fileName + Constants.INUSE_FILE_SUFFIX);
	}
}
