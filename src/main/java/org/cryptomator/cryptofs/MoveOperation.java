package org.cryptomator.cryptofs;

import static java.nio.file.StandardCopyOption.ATOMIC_MOVE;
import static java.nio.file.StandardCopyOption.COPY_ATTRIBUTES;

import java.io.IOException;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.CopyOption;
import java.nio.file.DirectoryStream;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.spi.FileSystemProvider;
import java.util.Optional;

import javax.inject.Inject;

import org.apache.commons.lang3.ArrayUtils;

@PerProvider
class MoveOperation {

	private final CopyOperation copyOperation;

	@Inject
	public MoveOperation(CopyOperation copyOperation) {
		this.copyOperation = copyOperation;
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
			boolean cleanup = true;
			try {
				copyOperation.copy(source, target, addCopyAttributesTo(options));
				success = true;
				cleanup = false;
			} catch (FileAlreadyExistsException | NoSuchFileException e) {
				cleanup = false;
			} finally {
				if (cleanup) {
					// do a best effort to clean a partially copied file
					try {
						provider(target).deleteIfExists(target);
					} catch (IOException e) {
						// ignore
					}
				}
			}
			if (success) {
				provider(source).deleteIfExists(source);
			}
		}
	}

	private boolean pathsBelongToSameFileSystem(CryptoPath source, CryptoPath target) {
		return source.getFileSystem() == target.getFileSystem();
	}

	private FileSystemProvider provider(CryptoPath path) {
		return path.getFileSystem().provider();
	}

	private CopyOption[] addCopyAttributesTo(CopyOption[] options) {
		CopyOption[] result = new CopyOption[options.length + 1];
		for (int i = 0; i < options.length; i++) {
			result[i] = options[i];
		}
		result[options.length] = COPY_ATTRIBUTES;
		return result;
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

}
