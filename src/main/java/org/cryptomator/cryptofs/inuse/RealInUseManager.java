package org.cryptomator.cryptofs.inuse;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import org.cryptomator.cryptofs.common.CacheUtils;
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
import java.time.format.DateTimeParseException;
import java.time.temporal.ChronoUnit;
import java.util.Optional;
import java.util.Properties;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

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

	private final ConcurrentHashMap<Path, RealUseToken> useTokens;
	private final Cache<Path, UseInfo> useInfoCache;
	private final Cache<Path, Object> ignoredInUseFiles;
	private final ScheduledExecutorService tokenRefresher;
	private final String owner;
	private final Cryptor cryptor;

	public RealInUseManager(@NonNull String owner, Cryptor cryptor) {
		this.owner = owner;
		this.cryptor = cryptor;
		this.useTokens = new ConcurrentHashMap<>();
		this.ignoredInUseFiles = Caffeine.newBuilder() //
				.expireAfterWrite(2, TimeUnit.MINUTES) //Do not keep the mark too long
				.maximumSize(100) //
				.build();
		this.useInfoCache = Caffeine.newBuilder() //
				.expireAfterWrite(5, TimeUnit.SECONDS) //
				.maximumSize(1000) //
				.build();
		this.tokenRefresher = Executors.newSingleThreadScheduledExecutor();
		tokenRefresher.scheduleWithFixedDelay(() -> useTokens.forEachValue(10L, RealUseToken::refresh), //
				REFRESH_DELAY_MINUTES, //
				REFRESH_DELAY_MINUTES, //
				TimeUnit.MINUTES);
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
	 *     <li> the in-use-file is currently not ignored</li>
	 * </ul>.
	 *
	 * @param inUseFilePath
	 * @return {@code true} if the in-use-file exists, but owned by different user
	 * @throws IOException if the in-use-file does not exist or cannot be read
	 * @throws IllegalArgumentException if the in-use-file is invalid
	 */
	boolean isInUse(Path inUseFilePath) throws IOException, IllegalArgumentException {
		if (ignoredInUseFiles.getIfPresent(inUseFilePath) != null) {
			return false;
		}

		var info = CacheUtils.getWithIOWrapped(inUseFilePath, useInfoCache, p -> {
			var content = readInUseFile(inUseFilePath);
			return validate(content);
		});

		return isInUse(info);
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

	//TODO: test
	UseInfo validate(Properties content) throws IllegalArgumentException {
		if (!content.containsKey(UseToken.OWNER_KEY)) {
			throw new IllegalArgumentException("Invalid in-use-file. Missing key %s".formatted(UseToken.OWNER_KEY));
		}
		if (!content.containsKey(UseToken.LASTUPDATED_KEY)) {
			throw new IllegalArgumentException("Invalid in-use-file. Missing key %s".formatted(UseToken.LASTUPDATED_KEY));
		}
		var stringTime = (String) content.get(UseToken.LASTUPDATED_KEY);
		try {
			var lastUpdated = Instant.parse(stringTime);
			return new UseInfo(owner, lastUpdated);
		} catch (DateTimeParseException e) {
			throw new IllegalArgumentException("Invalid in-use-file. Unable to parse content %s of key %s as UTC timestamp.".formatted(stringTime, UseToken.LASTUPDATED_KEY), e);
		}
	}

	boolean isInUse(UseInfo useInfo) {
		if (owner.equals(useInfo.owner())) {
			return false;
		}

		var timeSinceLastUpdate = Duration.between(useInfo.lastUpdated(), Instant.now());
		var threshold = Duration.of(2 * REFRESH_DELAY_MINUTES, ChronoUnit.MINUTES);
		return timeSinceLastUpdate.compareTo(threshold) < 0;
	}

	@Override
	public Optional<UseInfo> getUseInfo(Path ciphertextPath) {
		var inUseFilePath = computeInUseFilePath(ciphertextPath);
		return Optional.ofNullable(useInfoCache.getIfPresent(inUseFilePath));
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
			if (isInUse(inUseFilePath)) {
				throw new FileAlreadyInUseException(inUseFilePath);
			}
			ignoredInUseFiles.invalidate(inUseFilePath);
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
			throw new UncheckedIOException(e); //wrapped due to Map::compute method
		}
	}

	@Override
	public void ignoreInUse(Path ciphertextPath) {
		var inUseFilePath = computeInUseFilePath(ciphertextPath);
		ignoredInUseFiles.put(inUseFilePath, Boolean.TRUE);
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
	RealInUseManager(String owner, Cryptor cryptor, ConcurrentHashMap<Path, RealUseToken> useTokens, Cache<Path, Object> ignoredInUseFiles, Cache<Path, UseInfo> useInfoCache, ScheduledExecutorService tokenRefresher) {
		this.owner = owner;
		this.cryptor = cryptor;
		this.useTokens = useTokens;
		this.ignoredInUseFiles = ignoredInUseFiles;
		this.useInfoCache = useInfoCache;
		this.tokenRefresher = tokenRefresher;
	}
}
