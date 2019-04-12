package org.cryptomator.cryptofs;

import javax.inject.Inject;
import javax.inject.Singleton;
import java.io.IOException;
import java.nio.channels.FileChannel;
import java.nio.file.CopyOption;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.LinkOption;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributeView;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.EnumSet;
import java.util.Optional;

import static java.nio.file.StandardCopyOption.COPY_ATTRIBUTES;
import static java.nio.file.StandardCopyOption.REPLACE_EXISTING;
import static java.nio.file.StandardOpenOption.CREATE_NEW;
import static java.nio.file.StandardOpenOption.READ;
import static java.nio.file.StandardOpenOption.WRITE;

@Singleton
class CopyOperation {

	@Inject
	public CopyOperation() {
	}

	public void copy(CryptoPath source, CryptoPath target, CopyOption... options) throws IOException {
		if (source.equals(target)) {
			return;
		}
		LinkOption[] linkOptions = ArrayUtils.filterByType(options, LinkOption.class).toArray(LinkOption[]::new);
		if (source.getFileSystem() == target.getFileSystem()) {
			source.getFileSystem().copy(source, target, options);
		} else {
			Optional<BasicFileAttributes> sourceAttrs = attributes(source, linkOptions);
			Optional<BasicFileAttributes> targetAttrs = attributes(target, LinkOption.NOFOLLOW_LINKS);
			if (!sourceAttrs.isPresent()) {
				throw new NoSuchFileException(source.toString());
			}
			if (targetAttrs.isPresent()) {
				if (ArrayUtils.contains(options, REPLACE_EXISTING)) {
					target.getFileSystem().delete(target);
				} else {
					throw new FileAlreadyExistsException(target.toString());
				}
			}
			if (sourceAttrs.get().isDirectory()) {
				target.getFileSystem().createDirectory(target);
			} else if (sourceAttrs.get().isSymbolicLink()) {
				assert ArrayUtils.contains(linkOptions, LinkOption.NOFOLLOW_LINKS) : "if links were followed, source would not have been a symlink";
				transferSymlink(source, target);
			} else if (sourceAttrs.get().isRegularFile()) {
				transferRegularFile(source, target);
			} else {
				throw new UnsupportedOperationException("Unsupported file type: " + source);
			}
			if (ArrayUtils.contains(options, COPY_ATTRIBUTES)) {
				BasicFileAttributeView targetAttrView = target.getFileSystem().getFileAttributeView(target, BasicFileAttributeView.class, linkOptions);
				if (targetAttrView != null) {
					targetAttrView.setTimes(sourceAttrs.get().lastModifiedTime(), sourceAttrs.get().lastAccessTime(), sourceAttrs.get().creationTime());
				}
			}
		}
	}

	private void transferSymlink(CryptoPath source, CryptoPath target) throws IOException {
		Path linkTarget = source.getFileSystem().readSymbolicLink(source);
		target.getFileSystem().createSymbolicLink(target, linkTarget);
	}

	private void transferRegularFile(CryptoPath source, CryptoPath target) throws IOException {
		try (FileChannel sourceChannel = source.getFileSystem().newFileChannel(source, EnumSet.of(READ)); //
				FileChannel targetChannel = target.getFileSystem().newFileChannel(target, EnumSet.of(CREATE_NEW, WRITE))) {
			long transferred = 0;
			long toTransfer = sourceChannel.size();
			while (toTransfer > 0) {
				transferred += sourceChannel.transferTo(transferred, toTransfer, targetChannel);
				toTransfer = sourceChannel.size() - transferred;
			}
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
