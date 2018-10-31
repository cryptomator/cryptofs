package org.cryptomator.cryptofs;

import org.junit.Assert;
import org.junit.Test;
import org.mockito.Mockito;

import java.nio.file.attribute.PosixFileAttributes;
import java.nio.file.attribute.PosixFilePermission;
import java.util.EnumSet;
import java.util.Set;

import static java.nio.file.attribute.PosixFilePermission.*;
import static org.mockito.Mockito.mock;

public class CryptoPosixFileAttributesTest {

	private PosixFileAttributes delegate = mock(PosixFileAttributes.class);

	@Test
	public void testGetDelegateReturnsDelegate() {
		CryptoPosixFileAttributes attrs = new CryptoPosixFileAttributes(delegate, null, null, null, false);

		Assert.assertSame(attrs.getDelegate(), delegate);
	}

	@Test
	public void testGetPermissions() {
		CryptoPosixFileAttributes attrs = new CryptoPosixFileAttributes(delegate, null, null, null, false);
		Set<PosixFilePermission> delegatePermissions = EnumSet.allOf(PosixFilePermission.class);
		Mockito.when(delegate.permissions()).thenReturn(delegatePermissions);

		Assert.assertArrayEquals(delegatePermissions.toArray(), attrs.permissions().toArray());
	}

	@Test
	public void testGetPermissionsReadOnly() {
		CryptoPosixFileAttributes attrs = new CryptoPosixFileAttributes(delegate, null, null, null, true);
		Set<PosixFilePermission> delegatePermissions = EnumSet.allOf(PosixFilePermission.class);
		Mockito.when(delegate.permissions()).thenReturn(delegatePermissions);

		Assert.assertArrayEquals(EnumSet.of(OWNER_READ, GROUP_READ, OTHERS_READ, OWNER_EXECUTE, GROUP_EXECUTE, OTHERS_EXECUTE).toArray(), attrs.permissions().toArray());
	}

}
