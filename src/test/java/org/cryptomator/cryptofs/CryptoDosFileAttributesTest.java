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
import java.util.Optional;

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
	private OpenCryptoFile openCryptoFile = mock(OpenCryptoFile.class);

	private CryptoDosFileAttributes inTest = new CryptoDosFileAttributes(delegate, FILE, path, cryptor, Optional.of(openCryptoFile), false);

	@Test
	public void testIsArchiveDelegates() {
		assertThat(inTest.isArchive(), is(false));
	}

	@Test
	public void testIsHiddenIsFAlse() {
		assertThat(inTest.isHidden(), is(false));
	}

	@Theory
	public void testIsReadOnlyDelegates(boolean value) {
		when(delegate.isReadOnly()).thenReturn(value);

		CryptoDosFileAttributes attrs = new CryptoDosFileAttributes(delegate, FILE, path, cryptor, Optional.of(openCryptoFile), false);
		assertThat(attrs.isReadOnly(), is(value));
	}

	@Theory
	public void testIsReadOnlyForReadonlyFileSystem(boolean value) {
		when(delegate.isReadOnly()).thenReturn(value);

		CryptoDosFileAttributes attrs = new CryptoDosFileAttributes(delegate, FILE, path, cryptor, Optional.of(openCryptoFile), true);
		assertThat(attrs.isReadOnly(), is(true));
	}

	@Test
	public void testIsSystemDelegates() {
		assertThat(inTest.isSystem(), is(false));
	}

}
