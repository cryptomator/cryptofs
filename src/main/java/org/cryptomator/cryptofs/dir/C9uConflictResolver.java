package org.cryptomator.cryptofs.dir;

import jakarta.inject.Inject;
import org.cryptomator.cryptofs.common.Constants;
import org.cryptomator.cryptofs.common.StringUtils;
import org.cryptomator.cryptofs.inuse.InUseManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.file.Files;
import java.util.concurrent.CompletableFuture;
import java.util.regex.Matcher;
import java.util.stream.Stream;

import static org.cryptomator.cryptofs.common.Constants.BASE64_PATTERN;

/**
 * Resolves in-use file conflicts.
 */
@DirectoryStreamScoped
public class C9uConflictResolver {

	private static final Logger LOG = LoggerFactory.getLogger(C9uConflictResolver.class);
	private final InUseManager inUseManager;


	@Inject
	public C9uConflictResolver(InUseManager inUseManager) {
		this.inUseManager = inUseManager;
	}

	/**
	 * Processes files with {@value Constants#INUSE_FILE_SUFFIX} file extension. (in-use files)
	 * <p>
	 * If the in-use file is not valid base64 encoding, delete the file.
	 *
	 * @param node
	 * @return an empty stream.
	 */
	Stream<Node> process(Node node) {
		String basename = StringUtils.removeEnd(node.fullCiphertextFileName, Constants.INUSE_FILE_SUFFIX);
		Matcher matcher = BASE64_PATTERN.matcher(basename);
		matcher.region(0, basename.length());
		if (!matcher.matches()) { //any rename is considered bad
			LOG.debug("Found renamed in-use-file {}. Deleting it.", node.ciphertextPath);
			CompletableFuture.runAsync(() -> closeAndRemoveConflict(node, matcher));
		}
		return Stream.empty();
	}

	//visible for testing
	void closeAndRemoveConflict(Node node, Matcher matcher) {
		if (matcher.reset().find()) {
			var ciphertextFile = node.ciphertextPath.getParent().resolve(matcher.group() + Constants.CRYPTOMATOR_FILE_SUFFIX);
			inUseManager.checkUseStatus(ciphertextFile);
		}
		try {
			Files.deleteIfExists(node.ciphertextPath);
		} catch (IOException e) {
			LOG.debug("Failed to delete in-use-file {}. Retry on next directory listing.", node.ciphertextPath);
		}
	}

}
