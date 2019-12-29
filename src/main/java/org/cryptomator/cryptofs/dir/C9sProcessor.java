package org.cryptomator.cryptofs.dir;

import org.cryptomator.cryptofs.common.Constants;

import javax.inject.Inject;
import java.util.stream.Stream;

@DirectoryStreamScoped
class C9sProcessor {

	private final C9sInflator deflator;

	@Inject
	public C9sProcessor(C9sInflator deflator) {
		this.deflator = deflator;
	}

	public Stream<Node> process(Node node) {
		assert node.fullCiphertextFileName.endsWith(Constants.DEFLATED_FILE_SUFFIX);
		return deflator.process(node);
	}

}
