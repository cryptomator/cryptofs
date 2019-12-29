package org.cryptomator.cryptofs;

import org.cryptomator.cryptofs.common.Constants;

import java.nio.file.Path;
import java.util.Objects;
import java.util.Optional;

public class CiphertextFilePath {

	private final Path path;
	private final Optional<LongFileNameProvider.DeflatedFileName> deflatedFileName;

	CiphertextFilePath(Path path, Optional<LongFileNameProvider.DeflatedFileName> deflatedFileName) {
		this.path = Objects.requireNonNull(path);
		this.deflatedFileName = Objects.requireNonNull(deflatedFileName);
	}
	
	public Path getRawPath() {
		return path;
	}

	public boolean isShortened() {
		return deflatedFileName.isPresent();
	}

	public Path getFilePath() {
		return isShortened() ? path.resolve(Constants.CONTENTS_FILE_NAME) : path;
	}

	public Path getDirFilePath() {
		return path.resolve(Constants.DIR_FILE_NAME);
	}

	public Path getSymlinkFilePath() {
		return path.resolve(Constants.SYMLINK_FILE_NAME);
	}
	
	public Path getInflatedNamePath() {
		return path.resolve(Constants.INFLATED_FILE_NAME);
	}

	@Override
	public int hashCode() {
		return Objects.hash(path, deflatedFileName);
	}

	@Override
	public boolean equals(Object obj) {
		if (obj instanceof CiphertextFilePath) {
			CiphertextFilePath other = (CiphertextFilePath) obj;
			return this.path.equals(other.path) && this.deflatedFileName.equals(other.deflatedFileName);
		} else {
			return false;
		}
	}

	@Override
	public String toString() {
		return path.toString();
	}

	public void persistLongFileName() {
		deflatedFileName.ifPresent(LongFileNameProvider.DeflatedFileName::persist);
	}
}
