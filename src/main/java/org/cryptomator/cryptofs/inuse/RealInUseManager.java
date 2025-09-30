package org.cryptomator.cryptofs.inuse;

import org.cryptomator.cryptofs.common.Constants;
import org.cryptomator.cryptofs.common.EncryptedChannels;
import org.cryptomator.cryptolib.api.Cryptor;
import org.jspecify.annotations.NonNull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
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
	private static final int REFRESH_DELAY_MINUTES = 5;

	private final ConcurrentMap<Path, RealUseToken> useTokens;
	private final String owner;
	private final Cryptor cryptor;

	public RealInUseManager(@NonNull String owner, Cryptor cryptor) {
		this.owner = owner;
		this.cryptor = cryptor;
		this.useTokens = new ConcurrentHashMap<>();
	}


	@Override
	public boolean isInUseByOthers(Path ciphertextPath) {
		var inUseFilePath = computeInUseFilePath(ciphertextPath);
		if (useTokens.containsKey(inUseFilePath)) {
			return false;
		}

		try {
			return isInUse(inUseFilePath);
		} catch (IllegalArgumentException | IOException e) {
			return false;
		}
	}

	/**
	 * Reads the in-use-file at the given path, validates it and checks if
	 * <ul>
	 *     <li> this in-use-file belongs to the running crypto filesystem and</li>
	 *     <li> the last update time is at most 2*{@value #REFRESH_DELAY_MINUTES}</li> minutes ago
	 * </ul>.
	 *
	 * @param inUseFilePath
	 * @return {@code true} if the in-use-file exists, but owned by different user
	 * @throws IOException if the in-use-file does not exist or cannot be read
	 * @throws IllegalArgumentException if the in-use-file is invalid
	 */
	boolean isInUse(Path inUseFilePath) throws IOException, IllegalArgumentException {
		Properties content = readInUseFile(inUseFilePath);
		validate(content);
		return isInUse(content);
	}

	Properties readInUseFile(Path inUseFilePath) throws IOException, IllegalArgumentException {
		var bytes = ByteBuffer.allocate(Constants.INUSE_CLEARTEXT_SIZE);
		final int readBytes;
		try (var ch = Files.newByteChannel(inUseFilePath, StandardOpenOption.READ); //
			 var channel = EncryptedChannels.wrapDecryptionAround(ch, cryptor)) {
			readBytes = channel.read(bytes);
		}

		if (readBytes < 0) {
			throw new IllegalArgumentException("Empty cleartext inUse file");
		}

		var props = new Properties();
		try (var stream = new ByteArrayInputStream(bytes.array(), 0, readBytes)) {
			props.load(stream);
			return props;
		}
	}

	void validate(Properties content) throws IllegalArgumentException {
		if (!content.containsKey(UseToken.OWNER_KEY)) {
			throw new IllegalArgumentException("Invalid in-use-file. Missing key %s".formatted(UseToken.OWNER_KEY));
		}
		if (!content.containsKey(UseToken.LASTUPDATED_KEY)) {
			throw new IllegalArgumentException("Invalid in-use-file. Missing key %s".formatted(UseToken.LASTUPDATED_KEY));
		}
	}

	boolean isInUse(Properties content) {
		if (owner.equals(content.get(UseToken.OWNER_KEY))) {
			return false;
		}

		var lastUpdated = Instant.parse((String) content.get(UseToken.LASTUPDATED_KEY));
		var timeSinceLastUpdate = Duration.between(lastUpdated, Instant.now());
		var threshold = Duration.of(2 * REFRESH_DELAY_MINUTES, ChronoUnit.MINUTES);
		return timeSinceLastUpdate.compareTo(threshold) < 0;
	}

	/**
	 * Marks the given ciphertext path as in-use by this filesystem.
	 *
	 * @param ciphertextPath the path to the encrypted file intended to mark as "in-use"
	 * @return {@link UseToken} for marking ownership. It is either a {@link RealUseToken} on success or {@link  UseToken#CLOSED_TOKEN} on failure.
	 * @throws FileAlreadyInUseException if the file is already used by a different owner
	 */
	@Override
	public UseToken use(Path ciphertextPath) throws FileAlreadyInUseException {
		var inUseFilePath = computeInUseFilePath(ciphertextPath);
		try {
			return useTokens.computeIfAbsent(inUseFilePath, this::createInternal);
		} catch (UncheckedIOException e) {
			if (e.getCause() instanceof FileAlreadyInUseException inUseExc) {
				throw inUseExc;
			} else {
				//any other IOException. Already logged.
				return UseToken.CLOSED_TOKEN;
			}
		}
	}

	RealUseToken createInternal(Path inUseFilePath) throws UncheckedIOException {
		try {
			//TODO: performance idea: cache the result in a short lived cache (e.g. 5 seconds)
			if (isInUse(inUseFilePath)) {
				throw new FileAlreadyInUseException(inUseFilePath);
			}
			return RealUseToken.createWithExistingFile(inUseFilePath, owner, cryptor, useTokens);
		} catch (FileAlreadyInUseException e) {
			throw new UncheckedIOException(e); //wrapped due to Map::compute method
		} catch (NoSuchFileException e) {
			LOG.debug("No in-use-file {} found. Creating it.", inUseFilePath, e);
			return RealUseToken.createWithNewFile(inUseFilePath, owner, cryptor, useTokens);
		} catch (IllegalArgumentException e) {
			LOG.info("Found invalid in-use-file {}. Owning it.", inUseFilePath, e);
			return RealUseToken.createWithExistingFile(inUseFilePath, owner, cryptor, useTokens);
		} catch (IOException e) {
			LOG.warn("Failed to read in-use file {}. Ignoring it.", inUseFilePath, e);
			throw new UncheckedIOException(e);
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


	//for testing
	RealInUseManager(String owner, Cryptor cryptor, ConcurrentMap<Path, RealUseToken> useTokens) {
		this.owner = owner;
		this.cryptor = cryptor;
		this.useTokens = useTokens;
	}
}
