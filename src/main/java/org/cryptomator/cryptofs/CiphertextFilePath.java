package org.cryptomator.cryptofs;

import java.nio.file.Path;
import java.util.Objects;

public class CiphertextFilePath {

	private final Path path;
	private final boolean isShortened;

	// TODO: add deflatedName instead of caching it inside the longFileNameProvider
	CiphertextFilePath(Path path, boolean isShortened) {
		this.path = Objects.requireNonNull(path);
		this.isShortened = isShortened;
	}
	
	public Path getRawPath() {
		return path;
	}

	public boolean isShortened() {
		return isShortened;
	}

	public Path getFilePath() {
		return isShortened ? path.resolve(Constants.CONTENTS_FILE_NAME) : path;
	}

	public Path getDirFilePath() {
		return path.resolve(Constants.DIR_FILE_NAME);
	}

	public Path getSymlinkFilePath() {
		return path.resolve(Constants.SYMLINK_FILE_NAME);
	}

	@Override
	public int hashCode() {
		return Objects.hash(path, isShortened);
	}

	@Override
	public boolean equals(Object obj) {
		if (obj instanceof CiphertextFilePath) {
			CiphertextFilePath other = (CiphertextFilePath) obj;
			return this.path.equals(other.path) && this.isShortened == other.isShortened;
		} else {
			return false;
		}
	}

	@Override
	public String toString() {
		return path.toString();
	}
}
