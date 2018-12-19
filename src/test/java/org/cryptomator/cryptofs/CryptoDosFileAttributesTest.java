package org.cryptomator.cryptofs;

import org.cryptomator.cryptolib.api.Cryptor;
import org.junit.Rule;
import org.junit.Test;
import org.junit.experimental.theories.Theories;
import org.junit.experimental.theories.Theory;
import org.junit.rules.ExpectedException;
import org.junit.runner.RunWith;
import org.mockito.junit.MockitoJUnit;
import org.mockito.junit.MockitoRule;

import java.nio.file.attribute.DosFileAttributes;

import static org.cryptomator.cryptofs.CryptoPathMapper.CiphertextFileType.FILE;
import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@RunWith(Theories.class)
public class CryptoDosFileAttributesTest {

	@Rule
	public MockitoRule mockitoRule = MockitoJUnit.rule();

	@Rule
	public ExpectedException thrown = ExpectedException.none();

	private DosFileAttributes delegate = mock(DosFileAttributes.class);
	private CryptoPath path = mock(CryptoPath.class);
	private Cryptor cryptor = mock(Cryptor.class);

	private CryptoDosFileAttributes inTest = new CryptoDosFileAttributes(delegate, FILE, path, cryptor, null, false);

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
		CryptoDosFileAttributes attrs = new CryptoDosFileAttributes(delegate, FILE,null, null, null, false);
		when(delegate.isReadOnly()).thenReturn(value);

		assertThat(attrs.isReadOnly(), is(value));
	}

	@Theory
	public void testIsReadOnlyForReadonlyFileSystem(boolean value) {
		CryptoDosFileAttributes attrs = new CryptoDosFileAttributes(delegate, FILE,null, null, null, true);
		when(delegate.isReadOnly()).thenReturn(value);

		assertThat(attrs.isReadOnly(), is(true));
	}

	@Theory
	public void testIsSystemDelegates(boolean value) {
		when(delegate.isSystem()).thenReturn(value);

		assertThat(inTest.isSystem(), is(value));
	}

}
