package org.cryptomator.cryptofs;

import javax.inject.Inject;
import javax.inject.Singleton;
import java.nio.file.Path;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Singleton
class EncryptedNamePattern {
	
	private static final Pattern BASE64_PATTERN = Pattern.compile("([a-zA-Z0-9-_]{4})*[a-zA-Z0-9-_]{20}[a-zA-Z0-9-_=]{4}");

	@Inject
	public EncryptedNamePattern() {
	}

	public Optional<String> extractEncryptedName(Path ciphertextFile) {
		String name = ciphertextFile.getFileName().toString();
		Matcher matcher = BASE64_PATTERN.matcher(name);
		if (matcher.find(0)) {
			return Optional.of(matcher.group());
		} else {
			return Optional.empty();
		}
	}

}
