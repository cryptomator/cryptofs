/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptofs;

import org.hamcrest.Description;
import org.hamcrest.Matcher;
import org.hamcrest.MatcherAssert;
import org.hamcrest.TypeSafeMatcher;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

import static org.hamcrest.CoreMatchers.not;

public class GlobToRegexTest {

	@Test
	public void testAsteriskMatchesZeroOrMoreCharactersOfANameComponentWithoutCrossingDirectoryBoundaries() {
		MatcherAssert.assertThat("*", matches("test123#.txt"));
		MatcherAssert.assertThat("{*}", matches("test123#.txt"));
		MatcherAssert.assertThat("*/*", matches("test/123.txt"));
		MatcherAssert.assertThat("*/123.txt", matches("test/123.txt"));
		MatcherAssert.assertThat("*", doesNotMatch("test/123.txt"));

		MatcherAssert.assertThat("\\*", matches("*"));
		MatcherAssert.assertThat("{\\*}", matches("*"));
		MatcherAssert.assertThat("\\*", doesNotMatch("test123#.txt"));
	}

	@Test
	public void testDoubleAsteriskMatchesZeroOrMoreCharactersOfANameComponentWithCrossingDirectoryBoundaries() {
		MatcherAssert.assertThat("**", matches("test123#.txt"));
		MatcherAssert.assertThat("{**}", matches("test123#.txt"));
		MatcherAssert.assertThat("**", matches("test/123.txt"));
		MatcherAssert.assertThat("{**}", matches("test/123.txt"));

		MatcherAssert.assertThat("\\**", matches("*asdfoo"));
		MatcherAssert.assertThat("\\**", doesNotMatch("test/test123#.txt"));
	}

	@Test
	public void testQuestionMarkMatchesExactlyOneCharacterOfANameComponent() {
		MatcherAssert.assertThat("foo/ba?.txt", matches("foo/bar.txt"));
		MatcherAssert.assertThat("foo/ba{?}.txt", matches("foo/bar.txt"));
		MatcherAssert.assertThat("foo/???????", matches("foo/bar.txt"));
		MatcherAssert.assertThat("foo/???.txt", matches("foo/bar.txt"));
		MatcherAssert.assertThat("foo?bar.txt", doesNotMatch("foo/bar.txt"));
		MatcherAssert.assertThat("foo/?", doesNotMatch("foo/ba"));
	}

	@Test
	public void testSquareBracketsMatchSingleCharacterOutOfTheSet() {
		MatcherAssert.assertThat("[a-c]", matches("a"));
		MatcherAssert.assertThat("{[a-c]}", matches("a"));
		MatcherAssert.assertThat("[ac]", doesNotMatch("b"));
		MatcherAssert.assertThat("[ac-e]", matches("a"));
		MatcherAssert.assertThat("[ac-e]", matches("d"));
		MatcherAssert.assertThat("[a-c]", matches("c"));
		MatcherAssert.assertThat("[a-c]", doesNotMatch("d"));
	}

	@Test
	public void testNegatedSquareBracketsMatchSingleCharacterNotInTheSet() {
		MatcherAssert.assertThat("[!a-c]", doesNotMatch("a"));
		MatcherAssert.assertThat("{[!a-c]}", doesNotMatch("a"));
		MatcherAssert.assertThat("[!ac]", matches("b"));
		MatcherAssert.assertThat("[!ac-e]", doesNotMatch("a"));
		MatcherAssert.assertThat("[!ac-e]", doesNotMatch("d"));
		MatcherAssert.assertThat("[!a-c]", doesNotMatch("c"));
		MatcherAssert.assertThat("[!a-c]", matches("d"));
	}

	@Test
	public void testAsteriskQuestionMarkAndBackslashMatchThemselvesInSquareBrackets() {
		MatcherAssert.assertThat("[*]", matches("*"));
		MatcherAssert.assertThat("[?]", matches("?"));
		MatcherAssert.assertThat("[\\]", matches("\\"));
		MatcherAssert.assertThat("[-]", matches("-"));
		MatcherAssert.assertThat("[!-]", matches("a"));
		MatcherAssert.assertThat("[!-]", doesNotMatch("-"));
	}

	@Test
	public void testCurlyBracketsAreAlternatives() {
		MatcherAssert.assertThat("{abc,def,cde}", matches("abc"));
		MatcherAssert.assertThat("\\{abc,def,cde}", matches("{abc,def,cde}"));
		MatcherAssert.assertThat("{abc,def,cde}", matches("def"));
		MatcherAssert.assertThat("{abc,def,cd/e}", matches("cd/e"));
		MatcherAssert.assertThat("{abc,def,cd/e}", doesNotMatch("efg"));
	}

	@Test
	public void testEscapeAtEndOfPatternThrowsPatternSyntaxException() {
		Assertions.assertThrows(PatternSyntaxException.class, () -> {
			GlobToRegex.toRegex("asd\\", '/');
		});
	}

	@Test
	public void testEmptySquareBracketsThrowPatternSyntaxException() {
		Assertions.assertThrows(PatternSyntaxException.class, () -> {
			GlobToRegex.toRegex("[]", '/');
		});
	}

	@Test
	public void testUnclosedEmptySquareBracketsThrowPatternSyntaxException() {
		Assertions.assertThrows(PatternSyntaxException.class, () -> {
			GlobToRegex.toRegex("[", '/');
		});
	}

	@Test
	public void testUnclosedSquareBracketsThrowPatternSyntaxException() {
		Assertions.assertThrows(PatternSyntaxException.class, () -> {
			GlobToRegex.toRegex("[a", '/');
		});
	}

	@Test
	public void testNestedCurlyBracketsThrowPatternSyntaxException() {
		Assertions.assertThrows(PatternSyntaxException.class, () -> {
			GlobToRegex.toRegex("{a,{b},c}", '/');
		});
	}

	private Matcher<String> matches(String string) {
		return new TypeSafeMatcher<String>() {
			@Override
			public void describeTo(Description description) {
				description.appendText("matches ").appendText(string);
			}

			@Override
			protected boolean matchesSafely(String glob) {
				return Pattern.compile(GlobToRegex.toRegex(glob, '/')).matcher(string).matches();
			}
		};
	}

	private Matcher<String> doesNotMatch(String string) {
		return not(matches(string));
	}

}
