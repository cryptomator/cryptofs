package org.cryptomator.cryptofs.fh;

import jakarta.inject.Inject;
import org.cryptomator.cryptofs.CryptoFileSystemProperties;
import org.cryptomator.cryptofs.common.Constants;
import org.cryptomator.cryptofs.common.FileTooBigException;
import org.cryptomator.cryptofs.common.FileUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.Closeable;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.SeekableByteChannel;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.OpenOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.Properties;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;

@OpenFileScoped
public class InUseFile implements Closeable {

	private static final Logger LOG = LoggerFactory.getLogger(InUseFile.class);

	private final String fileSystemOwner;
	private final Properties info;
	private final AtomicReference<Path> currentFilePath;
	private SeekableByteChannel inUseFileChannel;

	private volatile boolean closed;

	@Inject
	public InUseFile(@CurrentOpenFilePath AtomicReference<Path> currentFilePath, //
					 CryptoFileSystemProperties fsProps) {
		this.currentFilePath = currentFilePath;
		this.fileSystemOwner = (String) fsProps.getOrDefault("owner", "cryptobot");
		this.info = new Properties();
		info.put("owner", fileSystemOwner);
	}

	synchronized boolean acquire() throws FileAlreadyInUseException {
		var ciphertextPath = currentFilePath.get();
		var inUseFilePath = computeInUseFilePath(ciphertextPath);
		var selfUseSuccessful = false;
		try {
			if (isInUseInternal(inUseFilePath, fileSystemOwner)) {
				throw new FileAlreadyInUseException(ciphertextPath);
			}
			selfUseSuccessful = updateInUseFile(inUseFilePath);
		} catch (FileAlreadyInUseException e) {
			throw e;
		} catch (NoSuchFileException e) {
			LOG.debug("No in-use-file for {} found. Creating it.", ciphertextPath, e);
			//TODO: delay creation with a CompletionStage (to prevent spam)
			selfUseSuccessful = createInUseFile(inUseFilePath);
		} catch (FileTooBigException | IllegalArgumentException e) {
			LOG.info("Found invalid in-use-file for {}. Owning it.", ciphertextPath, e);
			selfUseSuccessful = stealInUseFile(inUseFilePath);
		} catch (IOException e) {
			LOG.warn("Failed to read in-use file for {}. Ignoring it.", ciphertextPath, e);
		}
		return selfUseSuccessful;
	}

	private boolean updateInUseFile(Path inUseFilePath) {
		//TODO
		return true;
	}

	/**
	 * Reads the in-use-file at the given path, validates it and checks if this in-use-file belongs to the running cryptofile system.
	 *
	 * @return {@code true} if the in-use-file exists, is valid, but owned by different user. Otherwise {@code false}.
	 */
	public static boolean isInUse(Path ciphertextPath, String owner) {
		var inUseFile = computeInUseFilePath(ciphertextPath);
		try {
			return isInUseInternal(inUseFile, owner);
		} catch (IllegalArgumentException | IOException e) {
			return false;
		}
	}

	/**
	 * Reads the in-use-file at the given path, validates it and checks if this in-use-file belongs to the running cryptofile system.
	 *
	 * @param inUseFilePath
	 * @param fileSystemOwner name of the filesystem owner
	 * @return {@code true} if the in-use-file exists, but owned by different user
	 * @throws IOException if the in-use-file does not exist or cannot be read
	 * @throws IllegalArgumentException if the in-use-file is invalid
	 */
	static boolean isInUseInternal(Path inUseFilePath, String fileSystemOwner) throws IOException, IllegalArgumentException {
		Properties content = readInUseFile(inUseFilePath);
		if (!content.get("owner").equals(fileSystemOwner)) {
			//TODO: check also timestamps
			return true;
		}
		return false;
	}

	static Properties readInUseFile(Path inUseFilePath) throws IOException, IllegalArgumentException {
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

	private static void validate(Properties content) throws IllegalArgumentException {
		if (!content.containsKey("owner")) {
			throw new IllegalArgumentException("Invalid in-use-file. Missing key \"owner\"");
		}
		//TODO: more keys
	}

	boolean createInUseFile(Path inUseFilePath) {
		try {
			return writeInUseFile(inUseFilePath, Set.of(StandardOpenOption.WRITE, StandardOpenOption.CREATE_NEW));
		} catch (IOException e) {
			LOG.warn("Failed to create in-use file for {}.", inUseFilePath, e);
			return false;
		}
	}

	boolean stealInUseFile(Path inUseFilePath) {
		try {
			return writeInUseFile(inUseFilePath, Set.of(StandardOpenOption.WRITE, StandardOpenOption.TRUNCATE_EXISTING, StandardOpenOption.CREATE));
		} catch (IOException e) {
			LOG.warn("Failed to steal in-use file for {}.", inUseFilePath, e);
			return false;
		}
	}

	boolean writeInUseFile(Path inUseFilePath, Set<OpenOption> openOptions) throws IOException {
		this.inUseFileChannel = Files.newByteChannel(inUseFilePath, openOptions); //TODO: delete on close?
		var rawInfo = new ByteArrayOutputStream(4_000);
		info.store(rawInfo, "UNENCRYPTED Cryptomator inUse file");
		//TODO: encryption
		inUseFileChannel.write(ByteBuffer.wrap(rawInfo.toByteArray()));
		inUseFileChannel.position(0);
		return true;
	}

	//for testing
	void deleteInUseFile(Path inUseFilePath) throws IOException {
		Files.deleteIfExists(inUseFilePath);
	}

	synchronized void move(Path source) {
		var target = currentFilePath.get();
		try {
			Files.move(source, target);
		} catch (IOException e) {
			LOG.warn("Could not move in-use-file from {} to {}", source, target, e);
		}
	}


	@Override
	public synchronized void close() {
		if (closed) {
			return;
		}

		//always close
		this.closed = true;
		var ciphertextPath = currentFilePath.get();
		if (inUseFileChannel != null) {
			try {
				inUseFileChannel.close();
			} catch (IOException e) {
				LOG.warn("Unable to close in-use-file for {}. Must be cleaned manually.", ciphertextPath);
			}
			if (ciphertextPath != null) {
				var inUsePath = computeInUseFilePath(currentFilePath.get());
				try {
					deleteInUseFile(inUsePath);
				} catch (IOException e) {
					LOG.warn("Unable to delete in-use-file for {}. Must be cleaned manually.", inUsePath);
				}
			}
			//else: will be cleaned up by {@link CryptoFileSystem#delete}
		}
	}

	/**
	 * @param p a path with a filename ending with {@value Constants#CRYPTOMATOR_FILE_SUFFIX}
	 * @return a sibling path with the file extension {@value Constants#INUSE_FILE_SUFFIX}
	 */
	public static Path computeInUseFilePath(Path p) {
		var tmp = p.getFileName().toString();
		var fileName = tmp.substring(0, tmp.length() - Constants.CRYPTOMATOR_FILE_SUFFIX.length());
		return p.resolveSibling(fileName + Constants.INUSE_FILE_SUFFIX);
	}

	//-- for testing only

	InUseFile(AtomicReference<Path> currentFilePath, //
			  String fileSystemOwner, //
			  SeekableByteChannel inUseFileChannel, //
			  Properties info) {
		this.currentFilePath = currentFilePath;
		this.fileSystemOwner = fileSystemOwner;
		this.inUseFileChannel = inUseFileChannel;
		this.info = info;
	}
}
