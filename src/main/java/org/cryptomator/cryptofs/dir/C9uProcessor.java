package org.cryptomator.cryptofs.dir;

import jakarta.inject.Inject;
import org.cryptomator.cryptofs.common.Constants;

import java.util.stream.Stream;

/**
 * Processes in-use files (file extension {@value Constants#INUSE_FILE_SUFFIX}.
 */
@DirectoryStreamScoped
public class C9uProcessor {

	private final C9uConflictResolver conflictRemover;

	@Inject
	public C9uProcessor(C9uConflictResolver conflictRemover) {
		this.conflictRemover = conflictRemover;
	}

	public Stream<Node> process(Node node) {
		return conflictRemover.process(node);
	}
}
