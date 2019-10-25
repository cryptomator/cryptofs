package org.cryptomator.cryptofs.dir;

import java.nio.file.Path;
import java.util.Objects;

class NodeNames {

	public final Path ciphertextPath;
	public final String ciphertextFileName;
	public String ciphertextName;
	public String cleartextName;

	public NodeNames(Path ciphertextPath) {
		this.ciphertextPath = Objects.requireNonNull(ciphertextPath);
		this.ciphertextFileName = ciphertextPath.getFileName().toString();
	}

}
