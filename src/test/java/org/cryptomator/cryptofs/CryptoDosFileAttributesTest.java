package org.cryptomator.cryptofs;

import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.nio.file.attribute.DosFileAttributes;

import org.cryptomator.cryptolib.api.Cryptor;
import org.junit.Rule;
import org.junit.Test;
import org.junit.experimental.theories.Theories;
import org.junit.experimental.theories.Theory;
import org.junit.rules.ExpectedException;
import org.junit.runner.RunWith;
import org.mockito.junit.MockitoJUnit;
import org.mockito.junit.MockitoRule;

@RunWith(Theories.class)
public class CryptoDosFileAttributesTest {

	@Rule
	public MockitoRule mockitoRule = MockitoJUnit.rule();

	@Rule
	public ExpectedException thrown = ExpectedException.none();

	private DosFileAttributes delegate = mock(DosFileAttributes.class);
	private CryptoPath path = mock(CryptoPath.class);
	private Cryptor cryptor = mock(Cryptor.class);

	private CryptoDosFileAttributes inTest = new CryptoDosFileAttributes(delegate, path, cryptor);

	@Test
	public void testGetDelegateReturnsDelegate() {
		assertThat(inTest.getDelegate(), is(delegate));
	}

	@Theory
	public void testIsArchiveDelegates(boolean value) {
		when(delegate.isArchive()).thenReturn(value);

		assertThat(inTest.isArchive(), is(value));
	}

	@Theory
	public void testIsHiddenDelegates(boolean value) {
		when(delegate.isHidden()).thenReturn(value);

		assertThat(inTest.isHidden(), is(value));
	}

	@Theory
	public void testIsReadOnlyDelegates(boolean value) {
		when(delegate.isReadOnly()).thenReturn(value);

		assertThat(inTest.isReadOnly(), is(value));
	}

	@Theory
	public void testIsSystemDelegates(boolean value) {
		when(delegate.isSystem()).thenReturn(value);

		assertThat(inTest.isSystem(), is(value));
	}

}
