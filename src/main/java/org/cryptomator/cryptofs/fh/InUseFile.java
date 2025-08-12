package org.cryptomator.cryptofs.fh;

import jakarta.inject.Inject;
import org.cryptomator.cryptofs.CryptoFileSystemProperties;
import org.cryptomator.cryptofs.common.Constants;
import org.cryptomator.cryptofs.common.FileTooBigException;
import org.cryptomator.cryptofs.common.FileUtil;
import org.cryptomator.cryptofs.event.FileIsInUseEvent;
import org.cryptomator.cryptofs.event.FilesystemEvent;
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
import java.util.function.Consumer;

@OpenFileScoped
public class InUseFile implements Closeable {

	private static final Logger LOG = LoggerFactory.getLogger(InUseFile.class);

	private final String fileSystemOwner;
	private final Properties info;
	private final AtomicReference<Path> currentFilePath;
	private final Consumer<FilesystemEvent> eventConsumer;
	private SeekableByteChannel inUseFileChannel;

	private volatile Path lastKnownPath;

	@Inject
	public InUseFile(@CurrentOpenFilePath AtomicReference<Path> currentFilePath, //
					 Consumer<FilesystemEvent> eventConsumer, //
					 CryptoFileSystemProperties fsProps) {
		this.currentFilePath = currentFilePath;
		this.eventConsumer = eventConsumer;
		this.fileSystemOwner = (String) fsProps.getOrDefault("owner", "cryptobot");
		this.info = new Properties();
		info.put("owner", fileSystemOwner);
	}

	synchronized boolean acquire() throws FileAlreadyInUseException {
		var ciphertextPath = currentFilePath.get();
		var inUseFilePath = computeInUseFilePath(ciphertextPath);
		var selfUseSuccessful = false;
		try {
			if (isInUse(inUseFilePath, fileSystemOwner)) {
				eventConsumer.accept(new FileIsInUseEvent(Path.of("dummyCleartextPath"), ciphertextPath, info));
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

		if (selfUseSuccessful) {
			lastKnownPath = inUseFilePath; //TODO: to prevent two files point to the same file (and might delete the owner file on close, we need a map)
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
	 * @param inUseFilePath
	 * @param fileSystemOwner name of the filesystem owner
	 * @return {@code true} if the in-use-file exists, but owned by different user
	 * @throws IOException if the in-use-file does not exist or cannot be read
	 * @throws IllegalArgumentException if the in-use-file is invalid
	 */
	static boolean isInUse(Path inUseFilePath, String fileSystemOwner) throws IOException, IllegalArgumentException {
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


	@Override
	public synchronized void close() {
		var ciphertextPath = currentFilePath.get();
		if (inUseFileChannel != null) {
			try {
				//delay closing with a completionStage
				inUseFileChannel.close();
				var inUsePath = ciphertextPath != null? computeInUseFilePath(ciphertextPath) : lastKnownPath; //currentFilePath takes precedence
				deleteInUseFile(inUsePath);
			} catch (IOException e) {
				LOG.warn("Unable to delete in-use-file. Must be cleaned manually.");
			}
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
			  Consumer<FilesystemEvent> eventConsumer, //
			  String fileSystemOwner, //
			  SeekableByteChannel inUseFileChannel, //
			  Properties info) {
		this.currentFilePath = currentFilePath;
		this.eventConsumer = eventConsumer;
		this.fileSystemOwner = fileSystemOwner;
		this.inUseFileChannel = inUseFileChannel;
		this.info = info;
	}
}
