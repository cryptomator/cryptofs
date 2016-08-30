/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptofs;

import static org.hamcrest.CoreMatchers.not;
import static org.junit.Assert.assertThat;

import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

import org.hamcrest.Description;
import org.hamcrest.Matcher;
import org.hamcrest.TypeSafeMatcher;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

public class GlobToRegexTest {

	@Rule
	public ExpectedException thrown = ExpectedException.none();
	
	@Test
	public void testAsteriskMatchesZeroOrMoreCharactersOfANameComponentWithoutCrossingDirectoryBoundaries() {
		assertThat("*", matches("test123#.txt"));
		assertThat("{*}", matches("test123#.txt"));
		assertThat("*/*", matches("test/123.txt"));
		assertThat("*/123.txt", matches("test/123.txt"));
		assertThat("*", doesNotMatch("test/123.txt"));
		
		assertThat("\\*", matches("*"));
		assertThat("{\\*}", matches("*"));
		assertThat("\\*", doesNotMatch("test123#.txt"));
	}

	@Test
	public void testDoubleAsteriskMatchesZeroOrMoreCharactersOfANameComponentWithCrossingDirectoryBoundaries() {
		assertThat("**", matches("test123#.txt"));
		assertThat("{**}", matches("test123#.txt"));
		assertThat("**", matches("test/123.txt"));
		assertThat("{**}", matches("test/123.txt"));
		
		assertThat("\\**", matches("*asdfoo"));
		assertThat("\\**", doesNotMatch("test/test123#.txt"));
	}

	@Test
	public void testQuestionMarkMatchesExactlyOneCharacterOfANameComponent() {
		assertThat("foo/ba?.txt", matches("foo/bar.txt"));
		assertThat("foo/ba{?}.txt", matches("foo/bar.txt"));
		assertThat("foo/???????", matches("foo/bar.txt"));
		assertThat("foo/???.txt", matches("foo/bar.txt"));
		assertThat("foo?bar.txt", doesNotMatch("foo/bar.txt"));
		assertThat("foo/?", doesNotMatch("foo/ba"));
	}

	@Test
	public void testSquareBracketsMatchSingleCharacterOutOfTheSet() {
		assertThat("[a-c]", matches("a"));
		assertThat("{[a-c]}", matches("a"));
		assertThat("[ac]", doesNotMatch("b"));
		assertThat("[ac-e]", matches("a"));
		assertThat("[ac-e]", matches("d"));
		assertThat("[a-c]", matches("c"));
		assertThat("[a-c]", doesNotMatch("d"));
	}

	@Test
	public void testNegatedSquareBracketsMatchSingleCharacterNotInTheSet() {
		assertThat("[!a-c]", doesNotMatch("a"));
		assertThat("{[!a-c]}", doesNotMatch("a"));
		assertThat("[!ac]", matches("b"));
		assertThat("[!ac-e]", doesNotMatch("a"));
		assertThat("[!ac-e]", doesNotMatch("d"));
		assertThat("[!a-c]", doesNotMatch("c"));
		assertThat("[!a-c]", matches("d"));
	}

	@Test
	public void testAsteriskQuestionMarkAndBackslashMatchThemselvesInSquareBrackets() {
		assertThat("[*]", matches("*"));
		assertThat("[?]", matches("?"));
		assertThat("[\\]", matches("\\"));
		assertThat("[-]", matches("-"));
		assertThat("[!-]", matches("a"));
		assertThat("[!-]", doesNotMatch("-"));
	}

	@Test
	public void testCurlyBracketsAreAlternatives() {
		assertThat("{abc,def,cde}", matches("abc"));
		assertThat("\\{abc,def,cde}", matches("{abc,def,cde}"));
		assertThat("{abc,def,cde}", matches("def"));
		assertThat("{abc,def,cd/e}", matches("cd/e"));
		assertThat("{abc,def,cd/e}", doesNotMatch("efg"));
	}

	@Test
	public void testEscapeAtEndOfPatternThrowsPatternSyntaxException() {
		thrown.expect(PatternSyntaxException.class);
		
		GlobToRegex.toRegex("asd\\", '/');
	}

	@Test
	public void testEmptySquareBracketsThrowPatternSyntaxException() {
		thrown.expect(PatternSyntaxException.class);
		
		GlobToRegex.toRegex("[]", '/');
	}

	@Test
	public void testUnclosedEmptySquareBracketsThrowPatternSyntaxException() {
		thrown.expect(PatternSyntaxException.class);
		
		GlobToRegex.toRegex("[", '/');
	}

	@Test
	public void testUnclosedSquareBracketsThrowPatternSyntaxException() {
		thrown.expect(PatternSyntaxException.class);
		
		GlobToRegex.toRegex("[a", '/');
	}

	@Test
	public void testNestedCurlyBracketsThrowPatternSyntaxException() {
		thrown.expect(PatternSyntaxException.class);
		
		GlobToRegex.toRegex("{a,{b},c}", '/');
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
