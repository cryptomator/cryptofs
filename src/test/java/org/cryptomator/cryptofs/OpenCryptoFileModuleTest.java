package org.cryptomator.cryptofs;

import static org.cryptomator.cryptofs.OpenCryptoFileModule.openCryptoFileModule;
import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertThat;
import static org.mockito.Mockito.mock;

import java.nio.file.Path;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.mockito.junit.MockitoJUnit;
import org.mockito.junit.MockitoRule;

public class OpenCryptoFileModuleTest {

	@Rule
	public MockitoRule mockitoRule = MockitoJUnit.rule();

	@Rule
	public ExpectedException thrown = ExpectedException.none();

	private Path path = mock(Path.class);
	private EffectiveOpenOptions options = mock(EffectiveOpenOptions.class);
	private Runnable onClose = mock(Runnable.class);

	@Test
	public void testBuilder() {
		OpenCryptoFileModule inTest = openCryptoFileModule() //
				.withOptions(options) //
				.withPath(path) //
				.onClose(onClose) //
				.build();

		assertThat(inTest.provideOnClose(), is(onClose));
		assertThat(inTest.provideOptions(), is(options));
		assertThat(inTest.providePath(), is(path));
	}

	@Test
	public void testBuilderFailsIfPathIsMissing() {
		thrown.expect(IllegalStateException.class);

		openCryptoFileModule() //
				.withOptions(options) //
				.onClose(onClose) //
				.build();
	}

	@Test
	public void testBuilderFailsIfOptionsAreMissing() {
		thrown.expect(IllegalStateException.class);

		openCryptoFileModule() //
				.withPath(path) //
				.onClose(onClose) //
				.build();
	}

	@Test
	public void testBuilderIfOnCloseIsMissing() {
		thrown.expect(IllegalStateException.class);

		openCryptoFileModule() //
				.withOptions(options) //
				.withPath(path) //
				.build();
	}

}
