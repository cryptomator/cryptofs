package org.cryptomator.cryptofs.dir;

import java.nio.file.Path;
import java.util.Objects;

class Node {

	public final Path ciphertextPath;
	public final String fullCiphertextFileName;
	public String extractedCiphertext;
	public String cleartextName;

	public Node(Path ciphertextPath) {
		this.ciphertextPath = Objects.requireNonNull(ciphertextPath);
		this.fullCiphertextFileName = ciphertextPath.getFileName().toString();
	}

}
