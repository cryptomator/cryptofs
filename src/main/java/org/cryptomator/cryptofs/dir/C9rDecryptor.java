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

	public Stream<Node> process(Node node) {
		String basename = StringUtils.removeEnd(node.fullCiphertextFileName, Constants.CRYPTOMATOR_FILE_SUFFIX);
		Matcher matcher = BASE64_PATTERN.matcher(basename);
		Optional<Node> match = extractCiphertext(node, matcher, 0, basename.length());
		if (match.isPresent()) {
			return Stream.of(match.get());
		} else {
			return Stream.empty();
		}
	}

	private Optional<Node> extractCiphertext(Node node, Matcher matcher, int start, int end) {
		matcher.region(start, end);
		if (matcher.find()) {
			final MatchResult match = matcher.toMatchResult();
			final String validBase64 = match.group();
			assert validBase64.length() >= 24;
			assert match.end() - match.start() >= 24;
			try {
				node.cleartextName = cryptor.fileNameCryptor().decryptFilename(BaseEncoding.base64Url(), validBase64, dirId);
				node.extractedCiphertext = validBase64;
				return Optional.of(node);
			} catch (AuthenticationFailedException e) {
				// narrow down to sub-base64-sequences:
				int firstDelimIdx = DELIM_MATCHER.indexIn(validBase64);
				int lastDelimIdx = DELIM_MATCHER.lastIndexIn(validBase64);
				
				// fail fast if there is no way to find a different subsequence:
				if (firstDelimIdx == -1) {
					assert lastDelimIdx == -1;
					return Optional.empty();
				}

				// try matching with adjusted start and same end:
				int newStart = match.start() + Math.max(1, firstDelimIdx);
				assert match.start() >= start;
				assert newStart > start;
				Optional<Node> matchWithNewStart = extractCiphertext(node, matcher, newStart, end);
				if (matchWithNewStart.isPresent()) {
					return matchWithNewStart;
				}
				
				// try matching with same start and adjusted end:
				int delimDistanceFromEnd = validBase64.length() - lastDelimIdx;
				int newEnd = match.end() - Math.max(1, delimDistanceFromEnd);
				assert match.end() <= end;
				assert newEnd < end;
				Optional<Node> matchWithNewEnd = extractCiphertext(node, matcher, start, newEnd);
				if (matchWithNewEnd.isPresent()) {
					return matchWithNewEnd;
				}
			}
		}
		return Optional.empty();
	}
	
}
