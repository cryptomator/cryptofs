package org.cryptomator.cryptofs.fh;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

public class CiphertextFileKeyTest {

	private final CiphertextFileKey inTest = new CiphertextFileKey();

	private record Key(int id) {}

	@Test
	@DisplayName("every key matches while none was captured")
	public void testMatchesWithoutCapturedKey() {
		Assertions.assertFalse(inTest.isCaptured());
		Assertions.assertTrue(inTest.matches(new Key(1)));
	}

	@Test
	@DisplayName("an unknown key matches a captured one")
	public void testMatchesUnknownKey() {
		inTest.capture(new Key(1));

		Assertions.assertTrue(inTest.isCaptured());
		Assertions.assertTrue(inTest.matches(null));
	}

	@Test
	@DisplayName("an equal key matches")
	public void testMatchesEqualKey() {
		inTest.capture(new Key(1));

		Assertions.assertTrue(inTest.matches(new Key(1)));
	}

	@Test
	@DisplayName("a different key doesn't match")
	public void testDoesntMatchDifferentKey() {
		inTest.capture(new Key(1));

		Assertions.assertFalse(inTest.matches(new Key(2)));
	}

}
