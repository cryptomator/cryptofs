package org.cryptomator.cryptofs;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.io.IOException;
import java.nio.file.ReadOnlyFileSystemException;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class ReadonlyFlagTest {

	private CryptoFileSystemProperties properties = mock(CryptoFileSystemProperties.class);

	@DisplayName("isSet()")
	@ParameterizedTest(name = "readonlyFlag: {0} -> mounted readonly {0}")
	@ValueSource(booleans = {true, false})
	public void testIsSet(boolean readonly) {
		when(properties.readonly()).thenReturn(readonly);
		ReadonlyFlag inTest = new ReadonlyFlag(properties);

		boolean result = inTest.isSet();

		Assertions.assertEquals(readonly, result);
	}

	@DisplayName("assertWritable()")
	@ParameterizedTest(name = "readonlyFlag: {0} -> mounted readonly {0}")
	@ValueSource(booleans = {true, false})
	public void testAssertWritable(boolean readonly) {
		when(properties.readonly()).thenReturn(readonly);
		ReadonlyFlag inTest = new ReadonlyFlag(properties);

		if (readonly) {
			Assertions.assertThrows(ReadOnlyFileSystemException.class, () -> {
				inTest.assertWritable();
			});
		} else {
			Assertions.assertDoesNotThrow(() -> {
				inTest.assertWritable();
			});
		}
	}

}
