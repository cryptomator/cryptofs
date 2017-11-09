package org.cryptomator.cryptofs;

import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertThat;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Optional;

import org.junit.Test;

public class EncryptedNamePatternTest {

	private static final String ENCRYPTED_NAME = "ALKDUEEH2445375AUZEJFEFA";
	private static final Path PATH_WITHOUT_ENCRYPTED_NAME = Paths.get("foo.txt");
	private static final Path PATH_WITH_ENCRYPTED_NAME_AND_PREFIX_AND_SUFFIX = Paths.get("foo" + ENCRYPTED_NAME + ".txt");
	private static final Path PATH_WITH_ENCRYPTED_NAME_AND_SUFFIX = Paths.get(ENCRYPTED_NAME + ".txt");

	private EncryptedNamePattern inTest = new EncryptedNamePattern();

	@Test
	public void testExtractEncryptedNameReturnsEmptyOptionalIfNoEncryptedNameIsPresent() {
		Optional<String> result = inTest.extractEncryptedName(PATH_WITHOUT_ENCRYPTED_NAME);

		assertThat(result.isPresent(), is(false));
	}

	@Test
	public void testExtractEncryptedNameReturnsEncryptedNameIfItIsIsPresent() {
		Optional<String> result = inTest.extractEncryptedName(PATH_WITH_ENCRYPTED_NAME_AND_PREFIX_AND_SUFFIX);

		assertThat(result.isPresent(), is(true));
		assertThat(result.get(), is(ENCRYPTED_NAME));
	}

	@Test
	public void testExtractEncryptedNameFromStartReturnsEmptyOptionalIfNoEncryptedNameIsPresent() {
		Optional<String> result = inTest.extractEncryptedNameFromStart(PATH_WITHOUT_ENCRYPTED_NAME);

		assertThat(result.isPresent(), is(false));
	}

	@Test
	public void testExtractEncryptedNameFromStartReturnsEncryptedNameIfItIsPresent() {
		Optional<String> result = inTest.extractEncryptedName(PATH_WITH_ENCRYPTED_NAME_AND_SUFFIX);

		assertThat(result.isPresent(), is(true));
		assertThat(result.get(), is(ENCRYPTED_NAME));
	}

	@Test
	public void testExtractEncryptedNameFromStartReturnsEmptyOptionalIfEncryptedNameIsPresentAfterStart() {
		Optional<String> result = inTest.extractEncryptedNameFromStart(PATH_WITH_ENCRYPTED_NAME_AND_PREFIX_AND_SUFFIX);

		assertThat(result.isPresent(), is(false));
	}

}
