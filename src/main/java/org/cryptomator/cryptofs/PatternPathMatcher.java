package org.cryptomator.cryptofs;

import java.nio.file.Path;
import java.nio.file.PathMatcher;
import java.util.regex.Pattern;

class PatternPathMatcher implements PathMatcher {

	private final Pattern pattern;

	public PatternPathMatcher(Pattern pattern) {
		this.pattern = pattern;
	}

	/**
	 * @deprecated for testing
	 */
	@Deprecated
	Pattern getPattern() {
		return pattern;
	}

	@Override
	public boolean matches(Path path) {
		return pattern.matcher(path.toString()).matches();
	}

}
