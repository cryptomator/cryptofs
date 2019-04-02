package org.cryptomator.cryptofs;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Optional;

public class EncryptedNamePatternTest {

	private static final String ENCRYPTED_NAME = "ALKDUEEH2445375AUZEJFEFA";
	private static final Path PATH_WITHOUT_ENCRYPTED_NAME = Paths.get("foo.txt");
	private static final Path PATH_WITH_ENCRYPTED_NAME_AND_PREFIX_AND_SUFFIX = Paths.get("foo" + ENCRYPTED_NAME + ".txt");
	private static final Path PATH_WITH_ENCRYPTED_NAME_AND_SUFFIX = Paths.get(ENCRYPTED_NAME + ".txt");

	private EncryptedNamePattern inTest = new EncryptedNamePattern();

	@Test
	public void testExtractEncryptedNameReturnsEmptyOptionalIfNoEncryptedNameIsPresent() {
		Optional<String> result = inTest.extractEncryptedName(PATH_WITHOUT_ENCRYPTED_NAME);

		Assertions.assertFalse(result.isPresent());
	}

	@Test
	public void testExtractEncryptedNameReturnsEncryptedNameIfItIsIsPresent() {
		Optional<String> result = inTest.extractEncryptedName(PATH_WITH_ENCRYPTED_NAME_AND_PREFIX_AND_SUFFIX);

		Assertions.assertTrue(result.isPresent());
		Assertions.assertEquals(ENCRYPTED_NAME, result.get());
	}

	@Test
	public void testExtractEncryptedNameFromStartReturnsEmptyOptionalIfNoEncryptedNameIsPresent() {
		Optional<String> result = inTest.extractEncryptedNameFromStart(PATH_WITHOUT_ENCRYPTED_NAME);

		Assertions.assertFalse(result.isPresent());
	}

	@Test
	public void testExtractEncryptedNameFromStartReturnsEncryptedNameIfItIsPresent() {
		Optional<String> result = inTest.extractEncryptedName(PATH_WITH_ENCRYPTED_NAME_AND_SUFFIX);

		Assertions.assertTrue(result.isPresent());
		Assertions.assertEquals(ENCRYPTED_NAME, result.get());
	}

	@Test
	public void testExtractEncryptedNameFromStartReturnsEmptyOptionalIfEncryptedNameIsPresentAfterStart() {
		Optional<String> result = inTest.extractEncryptedNameFromStart(PATH_WITH_ENCRYPTED_NAME_AND_PREFIX_AND_SUFFIX);

		Assertions.assertFalse(result.isPresent());
	}

}
