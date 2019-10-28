package org.cryptomator.cryptofs.dir;

import javax.inject.Inject;
import java.util.stream.Stream;

@DirectoryStreamScoped
class C9rProcessor {

	private final C9rDecryptor decryptor;
	private final C9rConflictResolver conflictResolver;

	@Inject
	public C9rProcessor(C9rDecryptor decryptor, C9rConflictResolver conflictResolver){
		this.decryptor = decryptor;
		this.conflictResolver = conflictResolver;
	}

	public Stream<Node> process(Node node) {
		return decryptor.process(node).flatMap(conflictResolver::process);
	}
	
}
