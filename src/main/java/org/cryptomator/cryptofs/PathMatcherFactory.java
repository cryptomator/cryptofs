package org.cryptomator.cryptofs;

import java.nio.file.PathMatcher;
import java.util.regex.Pattern;

import javax.inject.Inject;

@PerProvider
class PathMatcherFactory {

	private final GlobToRegexConverter globToRegexConverter;

	@Inject
	public PathMatcherFactory(GlobToRegexConverter globToRegexConverter) {
		this.globToRegexConverter = globToRegexConverter;
	}

	public PathMatcher pathMatcherFrom(String syntaxAndPattern) {
		return new PatternPathMatcher(pattern(syntaxAndPattern));
	}

	private Pattern pattern(String syntaxAndPattern) {
		final String lowercaseSyntaxAndPattern = syntaxAndPattern.toLowerCase();
		if (lowercaseSyntaxAndPattern.startsWith("glob:")) {
			return Pattern.compile(globToRegexConverter.convert(syntaxAndPattern.substring(5)));
		} else if (lowercaseSyntaxAndPattern.startsWith("regex:")) {
			return Pattern.compile(syntaxAndPattern.substring(6));
		} else {
			throw new UnsupportedOperationException();
		}
	}

}
