package org.cryptomator.cryptofs;

import static java.nio.file.StandardCopyOption.ATOMIC_MOVE;
import static java.nio.file.StandardCopyOption.COPY_ATTRIBUTES;
import static java.nio.file.StandardCopyOption.REPLACE_EXISTING;
import static java.nio.file.StandardOpenOption.CREATE_NEW;
import static java.nio.file.StandardOpenOption.READ;
import static java.nio.file.StandardOpenOption.WRITE;

import java.io.IOException;
import java.nio.channels.FileChannel;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.CopyOption;
import java.nio.file.DirectoryStream;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributeView;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.spi.FileSystemProvider;
import java.util.EnumSet;
import java.util.Optional;

import javax.inject.Inject;

import org.apache.commons.lang3.ArrayUtils;

@PerProvider
class CopyAndMoveOperations {

	@Inject
	public CopyAndMoveOperations() {
	}

	public void copy(CryptoPath source, CryptoPath target, CopyOption... options) throws IOException {
		if (source.equals(target)) {
			return;
		}
		if (pathsBelongToSameFileSystem(source, target)) {
			source.getFileSystem().copy(source, target, options);
		} else {
			Optional<BasicFileAttributes> sourceAttrs = attributes(source);
			Optional<BasicFileAttributes> targetAttrs = attributes(target);
			if (!sourceAttrs.isPresent()) {
				throw new NoSuchFileException(source.toUri().toString());
			}
			if (targetAttrs.isPresent()) {
				if (ArrayUtils.contains(options, REPLACE_EXISTING)) {
					provider(target).delete(target);
				} else {
					throw new FileAlreadyExistsException(target.toUri().toString());
				}
			}
			if (sourceAttrs.get().isDirectory()) {
				provider(target).createDirectory(target);
			} else {
				transferFullFile(source, target);
			}
			if (ArrayUtils.contains(options, COPY_ATTRIBUTES)) {
				BasicFileAttributeView targetAttrView = provider(target).getFileAttributeView(target, BasicFileAttributeView.class);
				if (targetAttrView != null) {
					targetAttrView.setTimes(sourceAttrs.get().lastModifiedTime(), sourceAttrs.get().lastAccessTime(), sourceAttrs.get().creationTime());
				}
			}
		}
	}

	private void transferFullFile(CryptoPath source, CryptoPath target) throws IOException {
		try (FileChannel sourceChannel = provider(source).newFileChannel(source, EnumSet.of(READ)); //
				FileChannel targetChannel = provider(target).newFileChannel(target, EnumSet.of(CREATE_NEW, WRITE))) {
			long transferred = 0;
			long toTransfer = sourceChannel.size();
			while (toTransfer > 0) {
				transferred += sourceChannel.transferTo(transferred, toTransfer, targetChannel);
				toTransfer = sourceChannel.size() - transferred;
			}
		}
	}

	private FileSystemProvider provider(CryptoPath path) {
		return path.getFileSystem().provider();
	}

	public void move(CryptoPath source, CryptoPath target, CopyOption... options) throws IOException {
		if (source.equals(target)) {
			return;
		}
		if (pathsBelongToSameFileSystem(source, target)) {
			source.getFileSystem().move(source, target, options);
		} else {
			if (ArrayUtils.contains(options, ATOMIC_MOVE)) {
				throw new AtomicMoveNotSupportedException(source.toUri().toString(), target.toUri().toString(), "Move of encrypted file to different FileSystem");
			}
			if (isNonEmptyDirectory(source)) {
				throw new IOException("Can not move non empty directory to different FileSystem");
			}
			boolean success = false;
			try {
				copy(source, target, addCopyAttributesTo(options));
				success = true;
			} finally {
				if (!success) {
					// do a best effort to clean a partially copied file
					try {
						provider(target).deleteIfExists(target);
					} catch (IOException e) {
						// ignore
					}
				}
			}
			provider(source).deleteIfExists(source);
		}
	}

	private boolean pathsBelongToSameFileSystem(CryptoPath source, CryptoPath target) {
		return source.getFileSystem() == target.getFileSystem();
	}

	private boolean isNonEmptyDirectory(CryptoPath source) throws IOException {
		Optional<BasicFileAttributes> sourceAttrs = attributes(source);
		if (!sourceAttrs.map(BasicFileAttributes::isDirectory).orElse(false)) {
			return false;
		}
		try (DirectoryStream<Path> contents = provider(source).newDirectoryStream(source, ignored -> true)) {
			return contents.iterator().hasNext();
		}
	}

	private Optional<BasicFileAttributes> attributes(CryptoPath path) {
		try {
			return Optional.of(provider(path).readAttributes(path, BasicFileAttributes.class));
		} catch (IOException e) {
			return Optional.empty();
		}
	}

	private CopyOption[] addCopyAttributesTo(CopyOption[] options) {
		CopyOption[] result = new CopyOption[options.length + 1];
		for (int i = 0; i < options.length; i++) {
			result[i] = options[i];
		}
		result[options.length] = COPY_ATTRIBUTES;
		return result;
	}

}
