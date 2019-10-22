package org.cryptomator.cryptofs.dir;

import org.cryptomator.cryptofs.dir.EncryptedNamePattern;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.nio.file.Paths;
import java.util.Optional;

public class EncryptedNamePatternTest {
	
	private EncryptedNamePattern inTest = new EncryptedNamePattern();

	@ParameterizedTest
	@ValueSource(strings = {
			"aaaaBBBBcccc0000----__==",
			"?aaaaBBBBcccc0000----__==",
			"aaaaBBBBcccc0000----__== (conflict)",
			"?aaaaBBBBcccc0000----__== (conflict)",
	})
	public void testValidCiphertextNames(String name) {
		Optional<String> result = inTest.extractEncryptedName(Paths.get(name));

		Assertions.assertTrue(result.isPresent());
	}

	@ParameterizedTest
	@ValueSource(strings = {
			"tooShort",
			"aaaaBBBB====0000----__==",
	})
	public void testInvalidCiphertextNames(String name) {
		Optional<String> result = inTest.extractEncryptedName(Paths.get(name));

		Assertions.assertFalse(result.isPresent());
	}

}
