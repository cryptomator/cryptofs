package org.cryptomator.cryptofs.dir;

import java.nio.file.Path;

class NodeNames {

	private final Path ciphertextPath;
	private final Path inflatedPath;
	private final Path cleartextPath;

	public NodeNames(Path ciphertextPath) {
		this(ciphertextPath, null, null);
	}

	private NodeNames(Path ciphertextPath, Path inflatedPath, Path cleartextPath) {
		this.ciphertextPath = ciphertextPath;
		this.inflatedPath = inflatedPath;
		this.cleartextPath = cleartextPath;
	}

	public Path getCiphertextPath() {
		return ciphertextPath;
	}

	public Path getInflatedPath() {
		return inflatedPath;
	}

	public Path getCleartextPath() {
		return cleartextPath;
	}

	public NodeNames withCiphertextPath(Path ciphertextPath) {
		return new NodeNames(ciphertextPath, inflatedPath, cleartextPath);
	}

	public NodeNames withInflatedPath(Path inflatedPath) {
		return new NodeNames(ciphertextPath, inflatedPath, cleartextPath);
	}

	public NodeNames withCleartextPath(Path cleartextPath) {
		return new NodeNames(ciphertextPath, inflatedPath, cleartextPath);
	}

}
