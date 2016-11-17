package org.cryptomator.cryptofs;

import static org.hamcrest.CoreMatchers.instanceOf;
import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertThat;
import static org.mockito.Matchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.nio.file.PathMatcher;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.mockito.junit.MockitoJUnit;
import org.mockito.junit.MockitoRule;

public class PathMatcherFactoryTest {

	@Rule
	public MockitoRule mockitoRule = MockitoJUnit.rule();

	@Rule
	public ExpectedException thrown = ExpectedException.none();

	private GlobToRegexConverter globToRegexConverter = mock(GlobToRegexConverter.class);

	private PathMatcherFactory inTest = new PathMatcherFactory(globToRegexConverter);

	@Test
	public void testSyntaxAndPatternNotStartingWithGlobOrRegexThrowsUnsupportedOperationException() {
		thrown.expect(UnsupportedOperationException.class);

		inTest.pathMatcherFrom("fail");
	}

	@Test
	@SuppressWarnings("deprecation")
	public void testSyntaxAndPatternStartingWithRegexCreatesPatternPathMatcherWithCorrectPattern() {
		PathMatcher pathMatcher = inTest.pathMatcherFrom("regex:test[02]");

		assertThat(pathMatcher, is(instanceOf(PatternPathMatcher.class)));
		assertThat(((PatternPathMatcher) pathMatcher).getPattern().pattern(), is("test[02]"));
	}

	@Test
	@SuppressWarnings("deprecation")
	public void testSyntaxAndPatternStartingWithGlobCreatesPatternPathMatcherWithCorrectPattern() {
		String regexp = "test[abcd]*";
		when(globToRegexConverter.convert("abcd")).thenReturn(regexp);

		PathMatcher pathMatcher = inTest.pathMatcherFrom("glob:abcd");

		assertThat(pathMatcher, is(instanceOf(PatternPathMatcher.class)));
		assertThat(((PatternPathMatcher) pathMatcher).getPattern().pattern(), is(regexp));
	}

	@Test
	public void testSyntaxAndPatternIgnoresCase() {
		when(globToRegexConverter.convert(anyString())).thenReturn("a");

		inTest.pathMatcherFrom("reGEx:a");
		inTest.pathMatcherFrom("gLOb:a");
	}

}
