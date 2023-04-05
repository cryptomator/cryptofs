package org.cryptomator.cryptofs.dir;

import org.cryptomator.cryptofs.CryptoPathMapper;
import org.cryptomator.cryptofs.common.Constants;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Inject;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.stream.Stream;

@DirectoryStreamScoped
class BrokenDirectoryFilter {

	private static final Logger LOG = LoggerFactory.getLogger(BrokenDirectoryFilter.class);

	private final CryptoPathMapper cryptoPathMapper;

	@Inject
	public BrokenDirectoryFilter(CryptoPathMapper cryptoPathMapper) {
		this.cryptoPathMapper = cryptoPathMapper;
	}

	public Stream<Node> process(Node inputNode) {
		Path inputCiphertextPath = inputNode.ciphertextPath.resolve(Constants.DIR_FILE_NAME);
		if (Files.isRegularFile(inputCiphertextPath)) {
			final Path resolvedDirectoryPath;
			try {
				resolvedDirectoryPath = cryptoPathMapper.resolveDirectory(inputCiphertextPath).path;
			} catch (IOException e) {
				LOG.warn("Broken directory file: " + inputCiphertextPath, e);
				return Stream.empty();
			}
			if (!Files.isDirectory(resolvedDirectoryPath)) {
				LOG.warn("Broken directory file {}. Directory {} does not exist.", inputCiphertextPath, resolvedDirectoryPath);
				return Stream.empty();
			}
		}
		return Stream.of(inputNode);
	}

}
