package org.cryptomator.cryptofs;

import java.util.Objects;

//own file due to dagger

/**
 * Helper object to store the dir id of a directory along with its cleartext name (aka, the last element in the cleartext path)
 * @param dirId
 * @param clearNodeName
 */
record DirIdAndName(String dirId, String clearNodeName) {

	public DirIdAndName(String dirId, String clearNodeName) {
		this.dirId = Objects.requireNonNull(dirId);
		this.clearNodeName = Objects.requireNonNull(clearNodeName);
	}

}
