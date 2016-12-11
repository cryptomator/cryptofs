package org.cryptomator.cryptofs;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.mockito.Mockito.mock;

import java.nio.file.attribute.PosixFileAttributes;

import org.junit.Test;

public class CryptoPosixFileAttributesTest {

	private PosixFileAttributes delegate = mock(PosixFileAttributes.class);

	private CryptoPosixFileAttributes inTest = new CryptoPosixFileAttributes(delegate, null, null);

	@Test
	public void testGetDelegateReturnsDelegate() {
		assertThat(inTest.getDelegate(), is(delegate));
	}

}
