package org.cryptomator.cryptofs.fh;

import jakarta.inject.Inject;
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
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.Properties;
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

	@Inject
	public InUseFile(@CurrentOpenFilePath AtomicReference<Path> currentFilePath, Consumer<FilesystemEvent> eventConsumer) {
		this.currentFilePath = currentFilePath;
		this.eventConsumer = eventConsumer;
		this.fileSystemOwner = System.getenv("USERDOMAIN") + "\"" + System.getenv("USERNAME"); //TODO: read from CryptoFileSystemProperties
		this.info = new Properties();
		info.put("owner", fileSystemOwner);
	}

	boolean checkOrOwn() {
		var ciphertextPath = currentFilePath.get();
		var inUseFilePath = getInUseFilePath(ciphertextPath);
		try {
			Properties content = readInUseFile(inUseFilePath);
			if (content.get("owner").equals(fileSystemOwner)) {
				//update timestamps
				info.putAll(content);
				return false;
			} else {
				eventConsumer.accept(new FileIsInUseEvent(Path.of("yadda"), ciphertextPath, info));
				return true;
			}
		} catch (NoSuchFileException e) {
			LOG.debug("No in-use-file for {} found. Creating it.", ciphertextPath, e);
			createInUseFile(inUseFilePath);
		} catch (FileTooBigException e) {
			LOG.info("Found invalid in-use-file for {}. Owning it.", ciphertextPath, e);
			ownInUseFile(inUseFilePath);
		} catch (IOException e) {
			LOG.warn("Failed to read in-use file for {}. Ignoring it.", ciphertextPath, e);
		}
		return false;
	}

	Properties readInUseFile(Path inUseFilePath) throws IOException {
		//TODO: decryption
		var bytes = FileUtil.readAllBytesSizeRestricted(inUseFilePath, 4_000);
		//TODO: convert to JSON an extract info
		//	for now we use properties
		var props = new Properties();
		props.load(new ByteArrayInputStream(bytes));
		return props;
	}

	void createInUseFile(Path inUseFilePath) {
		try {
			this.inUseFileChannel = Files.newByteChannel(inUseFilePath, StandardOpenOption.DELETE_ON_CLOSE, StandardOpenOption.WRITE, StandardOpenOption.CREATE_NEW);
			writeInUseInfo();
		} catch (IOException e) {
			LOG.warn("Failed to create in-use file for {}.", inUseFilePath, e);
		}
	}

	void ownInUseFile(Path inUseFilePath) {
		try {
			this.inUseFileChannel = Files.newByteChannel(inUseFilePath, StandardOpenOption.DELETE_ON_CLOSE, StandardOpenOption.WRITE, StandardOpenOption.TRUNCATE_EXISTING, StandardOpenOption.CREATE);
			writeInUseInfo();
		} catch (IOException e) {
			LOG.warn("Failed to create in-use file for {}.", inUseFilePath, e);
		}
	}

	void writeInUseInfo() throws IOException {
		var rawInfo = new ByteArrayOutputStream(4_000);
		info.store(rawInfo, "UNENCRYPTED Cryptomator inUse file");
		//TODO: encryption
		this.inUseFileChannel.write(ByteBuffer.wrap(rawInfo.toByteArray()));
	}


	@Override
	public void close() {
		if (inUseFileChannel != null) {
			try {
				inUseFileChannel.close(); //TODO: DELETE_ON_CLOSE should clean up. Do we need a dedicated cleanup routine?
			} catch (IOException e) {
				LOG.error("Unable to delete in-use-file. Must be cleaned manually.");
			}
		}
	}

	/**
	 * @param p a path with a filename with a 3 character file extension
	 * @return a sibling path with the file extension replaced by "c9l"
	 */
	Path getInUseFilePath(Path p) {
		var ciphertextName = p.getFileName().toString();
		return p.resolveSibling(ciphertextName.substring(0, ciphertextName.length() - 3) + "c9l");
	}
}
