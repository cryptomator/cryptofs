package org.cryptomator.cryptofs;

import javax.inject.Inject;
import javax.inject.Singleton;
import java.nio.file.PathMatcher;
import java.util.regex.Pattern;

@Singleton
class PathMatcherFactory {

	private final GlobToRegexConverter globToRegexConverter;

	@Inject
	public PathMatcherFactory(GlobToRegexConverter globToRegexConverter) {
		this.globToRegexConverter = globToRegexConverter;
	}

	public PathMatcher pathMatcherFrom(String syntaxAndPattern) {
		PathMatcherStrategy strategy = getStrategy(syntaxAndPattern);
		return strategy.createPathMatcher(syntaxAndPattern);
	}

	private PathMatcherStrategy getStrategy(String syntaxAndPattern) {
		final String lowercaseSyntaxAndPattern = syntaxAndPattern.toLowerCase();
		if (lowercaseSyntaxAndPattern.startsWith("glob:")) {
			return new GlobPathMatcherStrategy();
		} else if (lowercaseSyntaxAndPattern.startsWith("regex:")) {
			return new RegexPathMatcherStrategy();
		} else {
			throw new UnsupportedOperationException();
		}
	}

	interface PathMatcherStrategy {
		PathMatcher createPathMatcher(String syntaxAndPattern);
	}

	class GlobPathMatcherStrategy implements PathMatcherStrategy {
		@Override
		public PathMatcher createPathMatcher(String syntaxAndPattern) {
			String pattern = globToRegexConverter.convert(syntaxAndPattern.substring(5));
			return new PatternPathMatcher(Pattern.compile(pattern));
		}
	}

	class RegexPathMatcherStrategy implements PathMatcherStrategy {
		@Override
		public PathMatcher createPathMatcher(String syntaxAndPattern) {
			String pattern = syntaxAndPattern.substring(6);
			return new PatternPathMatcher(Pattern.compile(pattern));
		}
	}

}

