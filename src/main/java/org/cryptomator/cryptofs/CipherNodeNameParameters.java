package org.cryptomator.cryptofs;

import java.util.Objects;

//own file due to dagger
public record CipherNodeNameParameters(String dirId, String clearNodeName) {

	public CipherNodeNameParameters(String dirId, String clearNodeName) {
		this.dirId = Objects.requireNonNull(dirId);
		this.clearNodeName = Objects.requireNonNull(clearNodeName);
	}

}
