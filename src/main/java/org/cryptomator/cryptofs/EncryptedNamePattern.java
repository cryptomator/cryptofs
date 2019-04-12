package org.cryptomator.cryptofs;

import javax.inject.Inject;
import javax.inject.Singleton;
import java.nio.file.Path;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Singleton
class EncryptedNamePattern {

	private static final Pattern BASE32_PATTERN = Pattern.compile("(0|1[A-Z0-9])?(([A-Z2-7]{8})*[A-Z2-7=]{8})");
	private static final Pattern BASE32_PATTERN_AT_START_OF_NAME = Pattern.compile("^(0|1[A-Z0-9])?(([A-Z2-7]{8})*[A-Z2-7=]{8})");

	@Inject
	public EncryptedNamePattern() {
	}

	public Optional<String> extractEncryptedName(Path ciphertextFile) {
		String name = ciphertextFile.getFileName().toString();
		Matcher matcher = BASE32_PATTERN.matcher(name);
		if (matcher.find(0)) {
			return Optional.of(matcher.group(2));
		} else {
			return Optional.empty();
		}
	}

	public Optional<String> extractEncryptedNameFromStart(Path ciphertextFile) {
		String name = ciphertextFile.getFileName().toString();
		Matcher matcher = BASE32_PATTERN_AT_START_OF_NAME.matcher(name);
		if (matcher.find(0)) {
			return Optional.of(matcher.group(2));
		} else {
			return Optional.empty();
		}
	}

}
