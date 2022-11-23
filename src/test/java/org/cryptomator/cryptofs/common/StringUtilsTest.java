package org.cryptomator.cryptofs.common;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EmptySource;
import org.junit.jupiter.params.provider.NullSource;
import org.junit.jupiter.params.provider.ValueSource;

public class StringUtilsTest {

	@Test
	@DisplayName("Exact matches are removed from the end of the string")
	public void testRemoveEndMatching() {
		String suffixToRemove = "Elephant";

		var result = StringUtils.removeEnd("WhiteElephant", suffixToRemove);
		Assertions.assertEquals("White", result);
	}

	@ParameterizedTest
	@ValueSource(strings = {"Whiteelephant", "asd", "WhiteElephantPeanut"})
	@NullSource
	@EmptySource
	public void testRemoveEndNotMatching(String toTest) {
		String suffixToRemove = "Elephant";

		var result = StringUtils.removeEnd(toTest, suffixToRemove);
		Assertions.assertEquals(toTest, result);
	}


}
