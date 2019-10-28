package org.cryptomator.cryptofs.dir;

import org.cryptomator.cryptofs.common.Constants;

import javax.inject.Inject;
import java.util.stream.Stream;

@DirectoryStreamScoped
class NodeProcessor {

	private final C9rProcessor c9rProcessor;
	private final C9sProcessor c9sProcessor;
	private final BrokenDirectoryFilter brokenDirFilter;

	@Inject
	public NodeProcessor(C9rProcessor c9rProcessor, C9sProcessor c9sProcessor, BrokenDirectoryFilter brokenDirFilter){
		this.c9rProcessor = c9rProcessor;
		this.c9sProcessor = c9sProcessor;
		this.brokenDirFilter = brokenDirFilter;
	}
	
	public Stream<Node> process(Node node) {
		if (node.fullCiphertextFileName.endsWith(Constants.CRYPTOMATOR_FILE_SUFFIX)) {
			return c9rProcessor.process(node).flatMap(brokenDirFilter::process);
		} else if (node.fullCiphertextFileName.endsWith(Constants.DEFLATED_FILE_SUFFIX)) {
			return c9sProcessor.process(node).flatMap(brokenDirFilter::process);
		} else {
			return Stream.empty();
		}
	}
	
}
