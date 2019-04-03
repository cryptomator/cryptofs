package org.cryptomator.cryptofs.attr;

import org.cryptomator.cryptofs.CryptoPath;
import org.hamcrest.MatcherAssert;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.LinkOption;
import java.nio.file.attribute.BasicFileAttributeView;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.DosFileAttributes;
import java.nio.file.attribute.FileTime;
import java.util.Map;

import static org.cryptomator.cryptofs.matchers.EntryMatcher.entry;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.is;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class AttributeByNameProviderTest {

	private AttributeProvider fileAttributeProvider = mock(AttributeProvider.class);
	private AttributeViewProvider fileAttributeViewProvider = mock(AttributeViewProvider.class);

	private CryptoPath path = mock(CryptoPath.class, "cleartextPath");

	private AttributeByNameProvider inTest = new AttributeByNameProvider(fileAttributeProvider, fileAttributeViewProvider);

	@Test
	public void testSetAttributeWithAttributeSucceeds() throws IOException {
		FileTime expectedFileTime = FileTime.fromMillis(4838388);
		BasicFileAttributeView fileAttributeView = mock(BasicFileAttributeView.class);
		when(fileAttributeViewProvider.getAttributeView(path, BasicFileAttributeView.class)).thenReturn(fileAttributeView);

		inTest.setAttribute(path, "creationTime", expectedFileTime);

		verify(fileAttributeView).setTimes(null, null, expectedFileTime);
	}

	@Test
	public void testSetAttributeWithBasicAttributeSucceeds() throws IOException {
		FileTime expectedFileTime = FileTime.fromMillis(4838388);
		BasicFileAttributeView fileAttributeView = mock(BasicFileAttributeView.class);
		when(fileAttributeViewProvider.getAttributeView(path, BasicFileAttributeView.class)).thenReturn(fileAttributeView);

		inTest.setAttribute(path, "basic:creationTime", expectedFileTime);

		verify(fileAttributeView).setTimes(null, null, expectedFileTime);
	}

	@Test
	public void testSetAttributeWithInvalidAttributeFails() throws IOException {
		IllegalArgumentException e = Assertions.assertThrows(IllegalArgumentException.class, () -> {
			inTest.setAttribute(path, "invalidAbc", null);
		});
		Assertions.assertEquals("Unrecognized attribute name: invalidAbc", e.getMessage());
	}

	@Test
	public void testReadAttributesWithNoAttrbiutesGivenFails() throws IOException {
		IllegalArgumentException e = Assertions.assertThrows(IllegalArgumentException.class, () -> {
			inTest.readAttributes(path, "");
		});
		Assertions.assertEquals("No attributes specified", e.getMessage());
	}

	@Test
	public void testReadBasicAttributesPassesThroughLinkOptions() throws IOException {
		FileTime creationTime = FileTime.fromMillis(4888333);
		BasicFileAttributes basicAttributes = mock(BasicFileAttributes.class);
		when(basicAttributes.creationTime()).thenReturn(creationTime);
		when(fileAttributeProvider.readAttributes(path, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS)).thenReturn(basicAttributes);

		inTest.readAttributes(path, "basic:creationTime", LinkOption.NOFOLLOW_LINKS);

		verify(fileAttributeProvider).readAttributes(path, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
	}

	@Test
	public void testReadBasicAttributesReturnsAttributeValues() throws IOException {
		FileTime creationTime = FileTime.fromMillis(4888333);
		BasicFileAttributes basicAttributes = mock(BasicFileAttributes.class);
		when(basicAttributes.creationTime()).thenReturn(creationTime);
		when(fileAttributeProvider.readAttributes(path, BasicFileAttributes.class)).thenReturn(basicAttributes);

		Map<String, Object> values = inTest.readAttributes(path, "basic:creationTime");

		System.out.println(values);

		MatcherAssert.assertThat(values.entrySet(), contains(entry(is("creationTime"), is(creationTime))));
	}

	@SuppressWarnings("unchecked")
	@Test
	public void testReadAllBasicAttributesReturnsAttributeValues() throws IOException {
		FileTime creationTime = FileTime.fromMillis(4888333);
		FileTime lastModifiedTime = FileTime.fromMillis(4888333);
		FileTime lastAccessTime = FileTime.fromMillis(4888333);
		boolean regularFile = true;
		boolean directory = false;
		boolean symbolicLink = false;
		boolean other = false;
		long size = 42L;
		Object fileKey = new Object();
		BasicFileAttributes basicAttributes = mock(BasicFileAttributes.class);
		when(basicAttributes.creationTime()).thenReturn(creationTime);
		when(basicAttributes.lastModifiedTime()).thenReturn(lastModifiedTime);
		when(basicAttributes.lastAccessTime()).thenReturn(lastAccessTime);
		when(basicAttributes.isRegularFile()).thenReturn(regularFile);
		when(basicAttributes.isDirectory()).thenReturn(directory);
		when(basicAttributes.isSymbolicLink()).thenReturn(symbolicLink);
		when(basicAttributes.isOther()).thenReturn(other);
		when(basicAttributes.size()).thenReturn(size);
		when(basicAttributes.fileKey()).thenReturn(fileKey);
		when(fileAttributeProvider.readAttributes(path, BasicFileAttributes.class)).thenReturn(basicAttributes);

		Map<String, Object> values = inTest.readAttributes(path, "basic:*");

		System.out.println(values);

		MatcherAssert.assertThat(values.entrySet(),
				containsInAnyOrder( //
						entry(is("creationTime"), is(creationTime)), //
						entry(is("lastModifiedTime"), is(lastModifiedTime)), //
						entry(is("lastAccessTime"), is(lastAccessTime)), //
						entry(is("isDirectory"), is(directory)), //
						entry(is("isRegularFile"), is(regularFile)), //
						entry(is("isOther"), is(other)), //
						entry(is("isSymbolicLink"), is(symbolicLink)), //
						entry(is("size"), is(size)), //
						entry(is("fileKey"), is(fileKey))));
	}

	@SuppressWarnings("unchecked")
	@Test
	public void testReadAllBasicAttributesWithoutViewNameReturnsAttributeValues() throws IOException {
		FileTime creationTime = FileTime.fromMillis(4888333);
		FileTime lastModifiedTime = FileTime.fromMillis(4888333);
		FileTime lastAccessTime = FileTime.fromMillis(4888333);
		boolean regularFile = true;
		boolean directory = false;
		boolean symbolicLink = false;
		boolean other = false;
		long size = 42L;
		Object fileKey = new Object();
		BasicFileAttributes basicAttributes = mock(BasicFileAttributes.class);
		when(basicAttributes.creationTime()).thenReturn(creationTime);
		when(basicAttributes.lastModifiedTime()).thenReturn(lastModifiedTime);
		when(basicAttributes.lastAccessTime()).thenReturn(lastAccessTime);
		when(basicAttributes.isRegularFile()).thenReturn(regularFile);
		when(basicAttributes.isDirectory()).thenReturn(directory);
		when(basicAttributes.isSymbolicLink()).thenReturn(symbolicLink);
		when(basicAttributes.isOther()).thenReturn(other);
		when(basicAttributes.size()).thenReturn(size);
		when(basicAttributes.fileKey()).thenReturn(fileKey);
		when(fileAttributeProvider.readAttributes(path, BasicFileAttributes.class)).thenReturn(basicAttributes);

		Map<String, Object> values = inTest.readAttributes(path, "*");

		System.out.println(values);

		MatcherAssert.assertThat(values.entrySet(),
				containsInAnyOrder( //
						entry(is("creationTime"), is(creationTime)), //
						entry(is("lastModifiedTime"), is(lastModifiedTime)), //
						entry(is("lastAccessTime"), is(lastAccessTime)), //
						entry(is("isDirectory"), is(directory)), //
						entry(is("isRegularFile"), is(regularFile)), //
						entry(is("isOther"), is(other)), //
						entry(is("isSymbolicLink"), is(symbolicLink)), //
						entry(is("size"), is(size)), //
						entry(is("fileKey"), is(fileKey))));
	}

	@SuppressWarnings("unchecked")
	@Test
	public void testReadDosAttributesReturnsAttributeValues() throws IOException {
		FileTime creationTime = FileTime.fromMillis(4888333);
		boolean hidden = true;
		boolean readOnly = false;
		BasicFileAttributes basicAttributes = mock(BasicFileAttributes.class);
		DosFileAttributes dosAttributes = mock(DosFileAttributes.class);
		when(basicAttributes.creationTime()).thenReturn(creationTime);
		when(dosAttributes.isHidden()).thenReturn(hidden);
		when(dosAttributes.isReadOnly()).thenReturn(readOnly);
		when(fileAttributeProvider.readAttributes(path, BasicFileAttributes.class)).thenReturn(basicAttributes);
		when(fileAttributeProvider.readAttributes(path, DosFileAttributes.class)).thenReturn(dosAttributes);

		Map<String, Object> values = inTest.readAttributes(path, "dos:readOnly,hidden");

		System.out.println(values);

		MatcherAssert.assertThat(values.entrySet(),
				containsInAnyOrder( //
						entry(is("readOnly"), is(readOnly)), //
						entry(is("hidden"), is(hidden))));
	}

}
