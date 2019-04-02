package org.cryptomator.cryptofs;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.nio.file.PathMatcher;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class PathMatcherFactoryTest {

	private GlobToRegexConverter globToRegexConverter = mock(GlobToRegexConverter.class);

	private PathMatcherFactory inTest = new PathMatcherFactory(globToRegexConverter);

	@Test
	public void testSyntaxAndPatternNotStartingWithGlobOrRegexThrowsUnsupportedOperationException() {
		Assertions.assertThrows(UnsupportedOperationException.class, () -> {
			inTest.pathMatcherFrom("fail");
		});
	}

	@Test
	@SuppressWarnings("deprecation")
	public void testSyntaxAndPatternStartingWithRegexCreatesPatternPathMatcherWithCorrectPattern() {
		PathMatcher pathMatcher = inTest.pathMatcherFrom("regex:test[02]");

		Assertions.assertTrue(pathMatcher instanceof PatternPathMatcher);
		Assertions.assertEquals("test[02]", ((PatternPathMatcher) pathMatcher).getPattern().pattern());
	}

	@Test
	@SuppressWarnings("deprecation")
	public void testSyntaxAndPatternStartingWithGlobCreatesPatternPathMatcherWithCorrectPattern() {
		String regexp = "test[abcd]*";
		when(globToRegexConverter.convert("abcd")).thenReturn(regexp);

		PathMatcher pathMatcher = inTest.pathMatcherFrom("glob:abcd");

		Assertions.assertTrue(pathMatcher instanceof PatternPathMatcher);
		Assertions.assertEquals(regexp, ((PatternPathMatcher) pathMatcher).getPattern().pattern());
	}

	@Test
	public void testSyntaxAndPatternIgnoresCase() {
		when(globToRegexConverter.convert(anyString())).thenReturn("a");

		inTest.pathMatcherFrom("reGEx:a");
		inTest.pathMatcherFrom("gLOb:a");
	}

}
