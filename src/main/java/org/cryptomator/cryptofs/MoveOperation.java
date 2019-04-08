package org.cryptomator.cryptofs;

import javax.inject.Inject;
import javax.inject.Singleton;
import java.io.IOException;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.CopyOption;
import java.nio.file.DirectoryStream;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.LinkOption;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.Arrays;
import java.util.Optional;

import static java.nio.file.StandardCopyOption.ATOMIC_MOVE;
import static java.nio.file.StandardCopyOption.COPY_ATTRIBUTES;

@Singleton
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
		if (source.getFileSystem() == target.getFileSystem()) {
			source.getFileSystem().move(source, target, options);
		} else {
			if (ArrayUtils.contains(options, ATOMIC_MOVE)) {
				throw new AtomicMoveNotSupportedException(source.toUri().toString(), target.toUri().toString(), "Move of encrypted file to different FileSystem");
			}
			if (isNonEmptyDirectory(source)) {
				// according to Files.move() JavaDoc:
				// "When moving a directory requires that its entries be moved then this method fails (by throwing an IOException)."
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
						target.getFileSystem().delete(target);
					} catch (IOException e) {
						// ignore
					}
				}
				if (success) {
					source.getFileSystem().delete(source);
				}
			}
		}
	}

	private CopyOption[] addCopyAttributesTo(CopyOption[] options) {
		CopyOption[] result = Arrays.copyOf(options, options.length + 1);
		result[result.length - 1] = COPY_ATTRIBUTES;
		return result;
	}

	private boolean isNonEmptyDirectory(CryptoPath source) throws IOException {
		Optional<BasicFileAttributes> sourceAttrs = attributes(source);
		if (!sourceAttrs.map(BasicFileAttributes::isDirectory).orElse(false)) {
			return false;
		}
		try (DirectoryStream<Path> contents = source.getFileSystem().newDirectoryStream(source, ignored -> true)) {
			return contents.iterator().hasNext();
		}
	}

	private Optional<BasicFileAttributes> attributes(CryptoPath path, LinkOption... linkOptions) {
		try {
			return Optional.of(path.getFileSystem().readAttributes(path, BasicFileAttributes.class, linkOptions));
		} catch (IOException e) {
			return Optional.empty();
		}
	}

}
