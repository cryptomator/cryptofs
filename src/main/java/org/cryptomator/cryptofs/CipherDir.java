package org.cryptomator.cryptofs;

import java.nio.file.Path;
import java.util.Objects;

//own file due to dagger
public record CipherDir(String dirId, Path contentDirPath) {

	public CipherDir(String dirId, Path contentDirPath) {
		this.dirId = Objects.requireNonNull(dirId);
		this.contentDirPath = Objects.requireNonNull(contentDirPath);
	}

}
