package org.cryptomator.cryptofs;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import java.util.Arrays;
import java.util.Set;
import java.util.stream.Collectors;

public class CiphertextFileTypeTest {

	@Test
	public void testNonTrivialValues() {
		Set<CiphertextFileType> result = CiphertextFileType.nonTrivialValues().collect(Collectors.toSet());
		Assertions.assertFalse(result.contains(CiphertextFileType.FILE));
		Assertions.assertTrue(result.containsAll(Arrays.asList(CiphertextFileType.DIRECTORY, CiphertextFileType.SYMLINK)));
	}

	@DisplayName("CiphertextFileType.forFileName(...)")
	@ParameterizedTest(name = "{0}")
	@CsvSource(value = {"FOO, ''", "0FOO, 0", "1SFOO, 1S", "1XFOO, ''"})
	public void testNonTrivialValues(String filename, String expectedPrefix) {
		CiphertextFileType result = CiphertextFileType.forFileName(filename);
		Assertions.assertEquals(expectedPrefix, result.getPrefix());
	}

}
