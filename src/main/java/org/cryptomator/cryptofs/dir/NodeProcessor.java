package org.cryptomator.cryptofs.dir;

import org.cryptomator.cryptofs.common.Constants;

import javax.inject.Inject;
import java.util.stream.Stream;

@DirectoryStreamScoped
class NodeProcessor {

	private final C9rProcessor c9rProcessor;

	@Inject
	public NodeProcessor(C9rProcessor c9rProcessor){
		this.c9rProcessor = c9rProcessor;
	}
	
	public Stream<Node> process(Node node) {
		if (node.fullCiphertextFileName.endsWith(Constants.CRYPTOMATOR_FILE_SUFFIX)) {
			return c9rProcessor.process(node);
		} else if (node.fullCiphertextFileName.endsWith(Constants.DEFLATED_FILE_SUFFIX)) {
			return Stream.empty();
		} else {
			return Stream.empty();
		}
	}
	
}
