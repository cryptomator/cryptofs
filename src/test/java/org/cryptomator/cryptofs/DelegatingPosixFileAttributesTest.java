package org.cryptomator.cryptofs;

import static java.nio.file.attribute.PosixFilePermission.GROUP_READ;
import static java.util.Arrays.asList;
import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.nio.file.attribute.GroupPrincipal;
import java.nio.file.attribute.PosixFileAttributes;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.UserPrincipal;
import java.util.HashSet;
import java.util.Set;

import org.junit.Rule;
import org.junit.Test;
import org.mockito.junit.MockitoJUnit;
import org.mockito.junit.MockitoRule;

public class DelegatingPosixFileAttributesTest {

	@Rule
	public MockitoRule mockitoRule = MockitoJUnit.rule();

	private PosixFileAttributes delegate = mock(PosixFileAttributes.class);

	private DelegatingPosixFileAttributes inTest = new DelegatingPosixFileAttributes() {
		@Override
		public PosixFileAttributes getDelegate() {
			return delegate;
		}
	};

	@Test
	public void testOwnerDelegatesToOwner() {
		UserPrincipal expectedOwner = mock(UserPrincipal.class);
		when(delegate.owner()).thenReturn(expectedOwner);

		UserPrincipal result = inTest.owner();

		assertThat(result, is(expectedOwner));
	}

	@Test
	public void testGroupDelegatesToGroup() {
		GroupPrincipal expectedGroup = mock(GroupPrincipal.class);
		when(delegate.group()).thenReturn(expectedGroup);

		GroupPrincipal result = inTest.group();

		assertThat(result, is(expectedGroup));
	}

	@Test
	public void testPermissionsDelegatesToPermissions() {
		Set<PosixFilePermission> expectedPermissions = new HashSet<>(asList(GROUP_READ));
		when(delegate.permissions()).thenReturn(expectedPermissions);

		Set<PosixFilePermission> result = inTest.permissions();

		assertThat(result, is(expectedPermissions));
	}

}
