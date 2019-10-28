package org.cryptomator.cryptofs.dir;

import com.google.common.io.BaseEncoding;
import org.cryptomator.cryptofs.LongFileNameProvider;
import org.cryptomator.cryptofs.common.Constants;
import org.cryptomator.cryptofs.common.StringUtils;
import org.cryptomator.cryptolib.api.AuthenticationFailedException;
import org.cryptomator.cryptolib.api.Cryptor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Inject;
import javax.inject.Named;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.stream.Stream;

@DirectoryStreamScoped
class C9sInflator {
	
	private static final Logger LOG = LoggerFactory.getLogger(C9sInflator.class);

	private final LongFileNameProvider longFileNameProvider;
	private final Cryptor cryptor;
	private final byte[] dirId;

	@Inject
	public C9sInflator(LongFileNameProvider longFileNameProvider, Cryptor cryptor, @Named("dirId") String dirId) {
		this.longFileNameProvider = longFileNameProvider;
		this.cryptor = cryptor;
		this.dirId = dirId.getBytes(StandardCharsets.US_ASCII);
	}

	public Stream<Node> process(Node node) {
		try {
			String c9rName = longFileNameProvider.inflate(node.ciphertextPath);
			node.extractedCiphertext = StringUtils.removeEnd(c9rName, Constants.CRYPTOMATOR_FILE_SUFFIX);
			node.cleartextName = cryptor.fileNameCryptor().decryptFilename(BaseEncoding.base64Url(), node.extractedCiphertext, dirId);
			return Stream.of(node);
		} catch (AuthenticationFailedException e) {
			LOG.warn(node.ciphertextPath + "'s inflated filename could not be decrypted.");
			return Stream.empty();
		} catch (IOException e) {
			LOG.warn(node.ciphertextPath + " could not be inflated.");
			return Stream.empty();
		}
	}

}
