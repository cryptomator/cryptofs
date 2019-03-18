package org.cryptomator.cryptofs;

import org.hamcrest.MatcherAssert;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.OpenOption;
import java.nio.file.ReadOnlyFileSystemException;
import java.util.HashSet;

import static java.nio.file.LinkOption.NOFOLLOW_LINKS;
import static java.nio.file.StandardOpenOption.APPEND;
import static java.nio.file.StandardOpenOption.CREATE;
import static java.nio.file.StandardOpenOption.CREATE_NEW;
import static java.nio.file.StandardOpenOption.DELETE_ON_CLOSE;
import static java.nio.file.StandardOpenOption.DSYNC;
import static java.nio.file.StandardOpenOption.READ;
import static java.nio.file.StandardOpenOption.SYNC;
import static java.nio.file.StandardOpenOption.TRUNCATE_EXISTING;
import static java.nio.file.StandardOpenOption.WRITE;
import static java.util.Arrays.asList;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class EffectiveOpenOptionsTest {

	private ReadonlyFlag falseReadonlyFlag = mock(ReadonlyFlag.class);
	private ReadonlyFlag trueReadonlyFlag = mock(ReadonlyFlag.class);
	private ReadOnlyFileSystemException readonlyException = new ReadOnlyFileSystemException();

	@BeforeEach
	public void setup() throws IOException {
		when(falseReadonlyFlag.isSet()).thenReturn(false);
		when(trueReadonlyFlag.isSet()).thenReturn(true);
		doThrow(readonlyException).when(trueReadonlyFlag).assertWritable();
	}

	@Test
	public void testFailIfAppendIsUsedWithRead() {
		Assertions.assertThrows(IllegalArgumentException.class, () -> {
			EffectiveOpenOptions.from(new HashSet<>(asList(APPEND, READ)), falseReadonlyFlag);
		});
	}

	@Test
	public void testFailIfAppendIsUsedWithTruncateExisting() {
		Assertions.assertThrows(IllegalArgumentException.class, () -> {
			EffectiveOpenOptions.from(new HashSet<>(asList(APPEND, TRUNCATE_EXISTING)), falseReadonlyFlag);
		});
	}

	@Test
	public void testUnsupportedOption() {
		Assertions.assertThrows(IllegalArgumentException.class, () -> {
			EffectiveOpenOptions.from(new HashSet<>(asList(new OpenOption() {
			})), falseReadonlyFlag);
		});
	}

	@Test
	public void testEmpty() throws IOException {
		EffectiveOpenOptions inTest = EffectiveOpenOptions.from(new HashSet<>(asList()), falseReadonlyFlag);

		Assertions.assertFalse(inTest.append());
		Assertions.assertFalse(inTest.create());
		Assertions.assertFalse(inTest.createNew());
		Assertions.assertFalse(inTest.deleteOnClose());
		Assertions.assertFalse(inTest.noFollowLinks());
		Assertions.assertTrue(inTest.readable());
		Assertions.assertFalse(inTest.syncData());
		Assertions.assertFalse(inTest.syncDataAndMetadata());
		Assertions.assertFalse(inTest.truncateExisting());
		Assertions.assertFalse(inTest.writable());

		MatcherAssert.assertThat(inTest.createOpenOptionsForEncryptedFile(), containsInAnyOrder(READ));
	}

	@Test
	public void testNoFollowLinks() throws IOException {
		EffectiveOpenOptions inTest = EffectiveOpenOptions.from(new HashSet<>(asList(NOFOLLOW_LINKS)), falseReadonlyFlag);

		Assertions.assertFalse(inTest.append());
		Assertions.assertFalse(inTest.create());
		Assertions.assertFalse(inTest.createNew());
		Assertions.assertFalse(inTest.deleteOnClose());
		Assertions.assertTrue(inTest.noFollowLinks());
		Assertions.assertTrue(inTest.readable());
		Assertions.assertFalse(inTest.syncData());
		Assertions.assertFalse(inTest.syncDataAndMetadata());
		Assertions.assertFalse(inTest.truncateExisting());
		Assertions.assertFalse(inTest.writable());

		MatcherAssert.assertThat(inTest.createOpenOptionsForEncryptedFile(), containsInAnyOrder(READ));
	}

	@Test
	public void testAppend() throws IOException {
		EffectiveOpenOptions inTest = EffectiveOpenOptions.from(new HashSet<>(asList(APPEND)), falseReadonlyFlag);

		Assertions.assertTrue(inTest.append());
		Assertions.assertFalse(inTest.create());
		Assertions.assertFalse(inTest.createNew());
		Assertions.assertFalse(inTest.deleteOnClose());
		Assertions.assertFalse(inTest.noFollowLinks());
		Assertions.assertFalse(inTest.readable());
		Assertions.assertFalse(inTest.syncData());
		Assertions.assertFalse(inTest.syncDataAndMetadata());
		Assertions.assertFalse(inTest.truncateExisting());
		Assertions.assertTrue(inTest.writable());

		MatcherAssert.assertThat(inTest.createOpenOptionsForEncryptedFile(), containsInAnyOrder(READ, WRITE));
	}

	@Test
	public void testCreate() throws IOException {
		EffectiveOpenOptions inTest = EffectiveOpenOptions.from(new HashSet<>(asList(CREATE)), falseReadonlyFlag);

		Assertions.assertFalse(inTest.append());
		Assertions.assertFalse(inTest.create());
		Assertions.assertFalse(inTest.createNew());
		Assertions.assertFalse(inTest.deleteOnClose());
		Assertions.assertFalse(inTest.noFollowLinks());
		Assertions.assertTrue(inTest.readable());
		Assertions.assertFalse(inTest.syncData());
		Assertions.assertFalse(inTest.syncDataAndMetadata());
		Assertions.assertFalse(inTest.truncateExisting());
		Assertions.assertFalse(inTest.writable());

		MatcherAssert.assertThat(inTest.createOpenOptionsForEncryptedFile(), containsInAnyOrder(READ));
	}

	@Test
	public void testCreateWithWrite() throws IOException {
		EffectiveOpenOptions inTest = EffectiveOpenOptions.from(new HashSet<>(asList(CREATE, WRITE)), falseReadonlyFlag);

		Assertions.assertFalse(inTest.append());
		Assertions.assertTrue(inTest.create());
		Assertions.assertFalse(inTest.createNew());
		Assertions.assertFalse(inTest.deleteOnClose());
		Assertions.assertFalse(inTest.noFollowLinks());
		Assertions.assertFalse(inTest.readable());
		Assertions.assertFalse(inTest.syncData());
		Assertions.assertFalse(inTest.syncDataAndMetadata());
		Assertions.assertFalse(inTest.truncateExisting());
		Assertions.assertTrue(inTest.writable());

		MatcherAssert.assertThat(inTest.createOpenOptionsForEncryptedFile(), containsInAnyOrder(CREATE, READ, WRITE));
	}

	@Test
	public void testCreateNew() throws IOException {
		EffectiveOpenOptions inTest = EffectiveOpenOptions.from(new HashSet<>(asList(CREATE_NEW)), falseReadonlyFlag);

		Assertions.assertFalse(inTest.append());
		Assertions.assertFalse(inTest.create());
		Assertions.assertFalse(inTest.createNew());
		Assertions.assertFalse(inTest.deleteOnClose());
		Assertions.assertFalse(inTest.noFollowLinks());
		Assertions.assertTrue(inTest.readable());
		Assertions.assertFalse(inTest.syncData());
		Assertions.assertFalse(inTest.syncDataAndMetadata());
		Assertions.assertFalse(inTest.truncateExisting());
		Assertions.assertFalse(inTest.writable());

		MatcherAssert.assertThat(inTest.createOpenOptionsForEncryptedFile(), containsInAnyOrder(READ));
	}

	@Test
	public void testCreateNewWithWrite() throws IOException {
		EffectiveOpenOptions inTest = EffectiveOpenOptions.from(new HashSet<>(asList(CREATE_NEW, WRITE)), falseReadonlyFlag);

		Assertions.assertFalse(inTest.append());
		Assertions.assertFalse(inTest.create());
		Assertions.assertTrue(inTest.createNew());
		Assertions.assertFalse(inTest.deleteOnClose());
		Assertions.assertFalse(inTest.noFollowLinks());
		Assertions.assertFalse(inTest.readable());
		Assertions.assertFalse(inTest.syncData());
		Assertions.assertFalse(inTest.syncDataAndMetadata());
		Assertions.assertFalse(inTest.truncateExisting());
		Assertions.assertTrue(inTest.writable());

		MatcherAssert.assertThat(inTest.createOpenOptionsForEncryptedFile(), containsInAnyOrder(CREATE_NEW, READ, WRITE));
	}

	@Test
	public void testCreateNewWithWriteAndCreate() throws IOException {
		EffectiveOpenOptions inTest = EffectiveOpenOptions.from(new HashSet<>(asList(CREATE, CREATE_NEW, WRITE)), falseReadonlyFlag);

		Assertions.assertFalse(inTest.append());
		Assertions.assertFalse(inTest.create());
		Assertions.assertTrue(inTest.createNew());
		Assertions.assertFalse(inTest.deleteOnClose());
		Assertions.assertFalse(inTest.noFollowLinks());
		Assertions.assertFalse(inTest.readable());
		Assertions.assertFalse(inTest.syncData());
		Assertions.assertFalse(inTest.syncDataAndMetadata());
		Assertions.assertFalse(inTest.truncateExisting());
		Assertions.assertTrue(inTest.writable());

		MatcherAssert.assertThat(inTest.createOpenOptionsForEncryptedFile(), containsInAnyOrder(CREATE_NEW, READ, WRITE));
	}

	@Test
	public void testDeleteOnClose() throws IOException {
		EffectiveOpenOptions inTest = EffectiveOpenOptions.from(new HashSet<>(asList(DELETE_ON_CLOSE)), falseReadonlyFlag);

		Assertions.assertFalse(inTest.append());
		Assertions.assertFalse(inTest.create());
		Assertions.assertFalse(inTest.createNew());
		Assertions.assertTrue(inTest.deleteOnClose());
		Assertions.assertFalse(inTest.noFollowLinks());
		Assertions.assertTrue(inTest.readable());
		Assertions.assertFalse(inTest.syncData());
		Assertions.assertFalse(inTest.syncDataAndMetadata());
		Assertions.assertFalse(inTest.truncateExisting());
		Assertions.assertFalse(inTest.writable());

		MatcherAssert.assertThat(inTest.createOpenOptionsForEncryptedFile(), containsInAnyOrder(READ, DELETE_ON_CLOSE));
	}

	@Test
	public void testRead() throws IOException {
		EffectiveOpenOptions inTest = EffectiveOpenOptions.from(new HashSet<>(asList(READ)), falseReadonlyFlag);

		Assertions.assertFalse(inTest.append());
		Assertions.assertFalse(inTest.create());
		Assertions.assertFalse(inTest.createNew());
		Assertions.assertFalse(inTest.deleteOnClose());
		Assertions.assertFalse(inTest.noFollowLinks());
		Assertions.assertTrue(inTest.readable());
		Assertions.assertFalse(inTest.syncData());
		Assertions.assertFalse(inTest.syncDataAndMetadata());
		Assertions.assertFalse(inTest.truncateExisting());
		Assertions.assertFalse(inTest.writable());

		MatcherAssert.assertThat(inTest.createOpenOptionsForEncryptedFile(), containsInAnyOrder(READ));
	}

	@Test
	public void testSync() throws IOException {
		EffectiveOpenOptions inTest = EffectiveOpenOptions.from(new HashSet<>(asList(SYNC)), falseReadonlyFlag);

		Assertions.assertFalse(inTest.append());
		Assertions.assertFalse(inTest.create());
		Assertions.assertFalse(inTest.createNew());
		Assertions.assertFalse(inTest.deleteOnClose());
		Assertions.assertFalse(inTest.noFollowLinks());
		Assertions.assertTrue(inTest.readable());
		Assertions.assertTrue(inTest.syncData());
		Assertions.assertTrue(inTest.syncDataAndMetadata());
		Assertions.assertFalse(inTest.truncateExisting());
		Assertions.assertFalse(inTest.writable());

		MatcherAssert.assertThat(inTest.createOpenOptionsForEncryptedFile(), containsInAnyOrder(READ, SYNC));
	}

	@Test
	public void testDSync() throws IOException {
		EffectiveOpenOptions inTest = EffectiveOpenOptions.from(new HashSet<>(asList(DSYNC)), falseReadonlyFlag);

		Assertions.assertFalse(inTest.append());
		Assertions.assertFalse(inTest.create());
		Assertions.assertFalse(inTest.createNew());
		Assertions.assertFalse(inTest.deleteOnClose());
		Assertions.assertFalse(inTest.noFollowLinks());
		Assertions.assertTrue(inTest.readable());
		Assertions.assertTrue(inTest.syncData());
		Assertions.assertFalse(inTest.syncDataAndMetadata());
		Assertions.assertFalse(inTest.truncateExisting());
		Assertions.assertFalse(inTest.writable());

		MatcherAssert.assertThat(inTest.createOpenOptionsForEncryptedFile(), containsInAnyOrder(READ, DSYNC));
	}

	@Test
	public void testTruncateExisting() throws IOException {
		EffectiveOpenOptions inTest = EffectiveOpenOptions.from(new HashSet<>(asList(TRUNCATE_EXISTING)), falseReadonlyFlag);

		Assertions.assertFalse(inTest.append());
		Assertions.assertFalse(inTest.create());
		Assertions.assertFalse(inTest.createNew());
		Assertions.assertFalse(inTest.deleteOnClose());
		Assertions.assertFalse(inTest.noFollowLinks());
		Assertions.assertTrue(inTest.readable());
		Assertions.assertFalse(inTest.syncData());
		Assertions.assertFalse(inTest.syncDataAndMetadata());
		Assertions.assertFalse(inTest.truncateExisting());
		Assertions.assertFalse(inTest.writable());

		MatcherAssert.assertThat(inTest.createOpenOptionsForEncryptedFile(), containsInAnyOrder(READ));
	}

	@Test
	public void testWrite() throws IOException {
		EffectiveOpenOptions inTest = EffectiveOpenOptions.from(new HashSet<>(asList(WRITE)), falseReadonlyFlag);

		Assertions.assertFalse(inTest.append());
		Assertions.assertFalse(inTest.create());
		Assertions.assertFalse(inTest.createNew());
		Assertions.assertFalse(inTest.deleteOnClose());
		Assertions.assertFalse(inTest.noFollowLinks());
		Assertions.assertFalse(inTest.readable());
		Assertions.assertFalse(inTest.syncData());
		Assertions.assertFalse(inTest.syncDataAndMetadata());
		Assertions.assertFalse(inTest.truncateExisting());
		Assertions.assertTrue(inTest.writable());

		MatcherAssert.assertThat(inTest.createOpenOptionsForEncryptedFile(), containsInAnyOrder(READ, WRITE));
	}

	@Test
	public void testEmptyWithTrueReadonlyFlag() throws IOException {
		EffectiveOpenOptions inTest = EffectiveOpenOptions.from(new HashSet<>(asList()), trueReadonlyFlag);

		Assertions.assertFalse(inTest.append());
		Assertions.assertFalse(inTest.create());
		Assertions.assertFalse(inTest.createNew());
		Assertions.assertFalse(inTest.deleteOnClose());
		Assertions.assertFalse(inTest.noFollowLinks());
		Assertions.assertTrue(inTest.readable());
		Assertions.assertFalse(inTest.syncData());
		Assertions.assertFalse(inTest.syncDataAndMetadata());
		Assertions.assertFalse(inTest.truncateExisting());
		Assertions.assertFalse(inTest.writable());

		MatcherAssert.assertThat(inTest.createOpenOptionsForEncryptedFile(), containsInAnyOrder(READ));
	}

	@Test
	public void testAppendTrueReadonlyFlag() {
		ReadOnlyFileSystemException e = Assertions.assertThrows(ReadOnlyFileSystemException.class, () -> {
			EffectiveOpenOptions.from(new HashSet<>(asList(APPEND)), trueReadonlyFlag);
		});
		Assertions.assertSame(readonlyException, e);
	}

	@Test
	public void testCreateTrueReadonlyFlag() throws IOException {
		EffectiveOpenOptions inTest = EffectiveOpenOptions.from(new HashSet<>(asList(CREATE)), trueReadonlyFlag);

		Assertions.assertFalse(inTest.append());
		Assertions.assertFalse(inTest.create());
		Assertions.assertFalse(inTest.createNew());
		Assertions.assertFalse(inTest.deleteOnClose());
		Assertions.assertFalse(inTest.noFollowLinks());
		Assertions.assertTrue(inTest.readable());
		Assertions.assertFalse(inTest.syncData());
		Assertions.assertFalse(inTest.syncDataAndMetadata());
		Assertions.assertFalse(inTest.truncateExisting());
		Assertions.assertFalse(inTest.writable());

		MatcherAssert.assertThat(inTest.createOpenOptionsForEncryptedFile(), containsInAnyOrder(READ));
	}

	@Test
	public void testCreateWithWriteTrueReadonlyFlag() {
		ReadOnlyFileSystemException e = Assertions.assertThrows(ReadOnlyFileSystemException.class, () -> {
			EffectiveOpenOptions.from(new HashSet<>(asList(CREATE, WRITE)), trueReadonlyFlag);
		});
		Assertions.assertSame(readonlyException, e);
	}

	@Test
	public void testCreateNewTrueReadonlyFlag() throws IOException {
		EffectiveOpenOptions inTest = EffectiveOpenOptions.from(new HashSet<>(asList(CREATE_NEW)), trueReadonlyFlag);

		Assertions.assertFalse(inTest.append());
		Assertions.assertFalse(inTest.create());
		Assertions.assertFalse(inTest.createNew());
		Assertions.assertFalse(inTest.deleteOnClose());
		Assertions.assertFalse(inTest.noFollowLinks());
		Assertions.assertTrue(inTest.readable());
		Assertions.assertFalse(inTest.syncData());
		Assertions.assertFalse(inTest.syncDataAndMetadata());
		Assertions.assertFalse(inTest.truncateExisting());
		Assertions.assertFalse(inTest.writable());

		MatcherAssert.assertThat(inTest.createOpenOptionsForEncryptedFile(), containsInAnyOrder(READ));
	}

	@Test
	public void testCreateNewWithWriteTrueReadonlyFlag() throws IOException {
		ReadOnlyFileSystemException e = Assertions.assertThrows(ReadOnlyFileSystemException.class, () -> {
			EffectiveOpenOptions.from(new HashSet<>(asList(CREATE_NEW, WRITE)), trueReadonlyFlag);
		});
		Assertions.assertSame(readonlyException, e);
	}

	@Test
	public void testCreateNewWithWriteAndCreateTrueReadonlyFlag() throws IOException {
		ReadOnlyFileSystemException e = Assertions.assertThrows(ReadOnlyFileSystemException.class, () -> {
			EffectiveOpenOptions.from(new HashSet<>(asList(CREATE, CREATE_NEW, WRITE)), trueReadonlyFlag);
		});
		Assertions.assertSame(readonlyException, e);
	}

	@Test
	public void testDeleteOnCloseTrueReadonlyFlag() throws IOException {
		ReadOnlyFileSystemException e = Assertions.assertThrows(ReadOnlyFileSystemException.class, () -> {
			EffectiveOpenOptions.from(new HashSet<>(asList(DELETE_ON_CLOSE)), trueReadonlyFlag);
		});
		Assertions.assertSame(readonlyException, e);
	}

	@Test
	public void testReadTrueReadonlyFlag() throws IOException {
		EffectiveOpenOptions inTest = EffectiveOpenOptions.from(new HashSet<>(asList(READ)), trueReadonlyFlag);

		Assertions.assertFalse(inTest.append());
		Assertions.assertFalse(inTest.create());
		Assertions.assertFalse(inTest.createNew());
		Assertions.assertFalse(inTest.deleteOnClose());
		Assertions.assertFalse(inTest.noFollowLinks());
		Assertions.assertTrue(inTest.readable());
		Assertions.assertFalse(inTest.syncData());
		Assertions.assertFalse(inTest.syncDataAndMetadata());
		Assertions.assertFalse(inTest.truncateExisting());
		Assertions.assertFalse(inTest.writable());

		MatcherAssert.assertThat(inTest.createOpenOptionsForEncryptedFile(), containsInAnyOrder(READ));
	}

	@Test
	public void testSyncTrueReadonlyFlag() throws IOException {
		EffectiveOpenOptions inTest = EffectiveOpenOptions.from(new HashSet<>(asList(SYNC)), trueReadonlyFlag);

		Assertions.assertFalse(inTest.append());
		Assertions.assertFalse(inTest.create());
		Assertions.assertFalse(inTest.createNew());
		Assertions.assertFalse(inTest.deleteOnClose());
		Assertions.assertFalse(inTest.noFollowLinks());
		Assertions.assertTrue(inTest.readable());
		Assertions.assertTrue(inTest.syncData());
		Assertions.assertTrue(inTest.syncDataAndMetadata());
		Assertions.assertFalse(inTest.truncateExisting());
		Assertions.assertFalse(inTest.writable());

		MatcherAssert.assertThat(inTest.createOpenOptionsForEncryptedFile(), containsInAnyOrder(READ, SYNC));
	}

	@Test
	public void testDSyncTrueReadonlyFlag() throws IOException {
		EffectiveOpenOptions inTest = EffectiveOpenOptions.from(new HashSet<>(asList(DSYNC)), trueReadonlyFlag);

		Assertions.assertFalse(inTest.append());
		Assertions.assertFalse(inTest.create());
		Assertions.assertFalse(inTest.createNew());
		Assertions.assertFalse(inTest.deleteOnClose());
		Assertions.assertFalse(inTest.noFollowLinks());
		Assertions.assertTrue(inTest.readable());
		Assertions.assertTrue(inTest.syncData());
		Assertions.assertFalse(inTest.syncDataAndMetadata());
		Assertions.assertFalse(inTest.truncateExisting());
		Assertions.assertFalse(inTest.writable());

		MatcherAssert.assertThat(inTest.createOpenOptionsForEncryptedFile(), containsInAnyOrder(READ, DSYNC));
	}

	@Test
	public void testTruncateExistingTrueReadonlyFlag() throws IOException {
		EffectiveOpenOptions inTest = EffectiveOpenOptions.from(new HashSet<>(asList(TRUNCATE_EXISTING)), trueReadonlyFlag);

		Assertions.assertFalse(inTest.append());
		Assertions.assertFalse(inTest.create());
		Assertions.assertFalse(inTest.createNew());
		Assertions.assertFalse(inTest.deleteOnClose());
		Assertions.assertFalse(inTest.noFollowLinks());
		Assertions.assertTrue(inTest.readable());
		Assertions.assertFalse(inTest.syncData());
		Assertions.assertFalse(inTest.syncDataAndMetadata());
		Assertions.assertFalse(inTest.truncateExisting());
		Assertions.assertFalse(inTest.writable());

		MatcherAssert.assertThat(inTest.createOpenOptionsForEncryptedFile(), containsInAnyOrder(READ));
	}

	@Test
	public void testWriteTrueReadonlyFlag() {
		ReadOnlyFileSystemException e = Assertions.assertThrows(ReadOnlyFileSystemException.class, () -> {
			EffectiveOpenOptions.from(new HashSet<>(asList(WRITE)), trueReadonlyFlag);
		});
		Assertions.assertSame(readonlyException, e);
	}

}
