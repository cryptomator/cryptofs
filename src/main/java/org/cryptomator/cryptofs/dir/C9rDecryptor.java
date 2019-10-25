package org.cryptomator.cryptofs.dir;

import com.google.common.base.CharMatcher;
import com.google.common.io.BaseEncoding;
import org.cryptomator.cryptofs.common.Constants;
import org.cryptomator.cryptofs.common.StringUtils;
import org.cryptomator.cryptolib.api.AuthenticationFailedException;
import org.cryptomator.cryptolib.api.Cryptor;

import javax.inject.Inject;
import javax.inject.Named;
import java.nio.charset.StandardCharsets;
import java.util.Optional;
import java.util.regex.MatchResult;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

@DirectoryStreamScoped
class C9rDecryptor {

	// visible for testing:
	static final Pattern BASE64_PATTERN = Pattern.compile("([a-zA-Z0-9-_]{4})*[a-zA-Z0-9-_]{20}[a-zA-Z0-9-_=]{4}");
	private static final CharMatcher DELIM_MATCHER = CharMatcher.anyOf("_-");

	private final Cryptor cryptor;
	private final byte[] dirId;

	@Inject
	public C9rDecryptor(Cryptor cryptor, @Named("dirId") String dirId) {
		this.cryptor = cryptor;
		this.dirId = dirId.getBytes(StandardCharsets.US_ASCII);
	}

	public Stream<NodeNames> process(NodeNames nodeNames) {
		String basename = StringUtils.removeEnd(nodeNames.ciphertextFileName, Constants.CRYPTOMATOR_FILE_SUFFIX);
		Matcher matcher = BASE64_PATTERN.matcher(basename);
		Optional<NodeNames> match = extractCiphertext(nodeNames, matcher, 0, basename.length());
		if (match.isPresent()) {
			return Stream.of(match.get());
		} else {
			return Stream.empty();
		}
	}

	private Optional<NodeNames> extractCiphertext(NodeNames nodeNames, Matcher matcher, int start, int end) {
		matcher.region(start, end);
		if (matcher.find()) {
			final MatchResult matchResult = matcher.toMatchResult();
			final String validBase64 = matchResult.group();
			assert validBase64.length() >= 24;
			assert matchResult.end() - matchResult.start() >= 24;
			try {
				nodeNames.cleartextName = cryptor.fileNameCryptor().decryptFilename(BaseEncoding.base64Url(), validBase64, dirId);
				nodeNames.ciphertextName = validBase64;
				return Optional.of(nodeNames);
			} catch (AuthenticationFailedException e) {
				// narrow down to sub-base64-sequences:
				int firstDelimIdx = DELIM_MATCHER.indexIn(validBase64);
				int lastDelimIdx = DELIM_MATCHER.lastIndexIn(validBase64);
				if (firstDelimIdx == -1) {
					assert lastDelimIdx == -1;
					return Optional.empty();
				}
				assert firstDelimIdx != -1;
				assert lastDelimIdx != -1;
				Optional<NodeNames> subsequenceMatch = Optional.empty();
				if (!subsequenceMatch.isPresent() && firstDelimIdx == 0) {
					subsequenceMatch = extractCiphertext(nodeNames, matcher, matchResult.start() + 1, end);
				}
				if (!subsequenceMatch.isPresent() && lastDelimIdx == validBase64.length() - 1) {
					subsequenceMatch = extractCiphertext(nodeNames, matcher, start, matchResult.end() - 1);
				}
				if (!subsequenceMatch.isPresent() && firstDelimIdx > 0) {
					subsequenceMatch = extractCiphertext(nodeNames, matcher, matchResult.start() + firstDelimIdx, end);
				}
				if (!subsequenceMatch.isPresent() && lastDelimIdx < validBase64.length() - 1) {
					subsequenceMatch = extractCiphertext(nodeNames, matcher, start, matchResult.start() + lastDelimIdx);
				}
				return subsequenceMatch;
			}
		} else {
			return Optional.empty();
		}
	}
	
}
