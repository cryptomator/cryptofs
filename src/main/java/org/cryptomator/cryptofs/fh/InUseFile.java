package org.cryptomator.cryptofs.fh;

import jakarta.inject.Inject;
import org.cryptomator.cryptofs.common.FileTooBigException;
import org.cryptomator.cryptofs.common.FileUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.Closeable;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.SeekableByteChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.concurrent.atomic.AtomicReference;

@OpenFileScoped
public class InUseFile implements Closeable {

	private static final Logger LOG = LoggerFactory.getLogger(InUseFile.class);

	private final AtomicReference<Path> currentFilePath;
	private SeekableByteChannel inUseFileChannel;

	@Inject
	public InUseFile(@CurrentOpenFilePath AtomicReference<Path> currentFilePath) {
		//TODO: add notifier
		this.currentFilePath = currentFilePath;
	}

	boolean checkOrOwn() {
		var ciphertextPath = currentFilePath.get();
		var inUseFilePath = getInUseFilePath(ciphertextPath);
		try {
			Object content = readInUseFile(inUseFilePath);
			//check if file belongs to us
			//if yes, do stuff and return false
			//otherwise notify user and return true
			return true;
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

	Object readInUseFile(Path inUseFilePath) throws IOException {
		var bytes = FileUtil.readAllBytesSizeRestricted(inUseFilePath, 4_000);
		//TODO: convert to JSON an extract info
		return new Object();
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
		this.inUseFileChannel.write(ByteBuffer.wrap("Test String".getBytes(StandardCharsets.UTF_8)));
	}


	@Override
	public void close() {
		if (inUseFileChannel != null) {
			try {
				inUseFileChannel.close(); //TODO: DELETE_ON_CLOSE should clean up. Do we need a dedicated cleanup routine?
			} catch (IOException e) {
				LOG.error("Unable to delete in-use-file. Must be cleaned manually.");
				//throw new RuntimeException(e);
			}
		}
	}

	private Path getInUseFilePath(Path p) {
		var ciphertextName = p.getFileName().toString();
		return p.resolveSibling(ciphertextName.substring(0, ciphertextName.length() - 3) + "c9l");
	}
}
