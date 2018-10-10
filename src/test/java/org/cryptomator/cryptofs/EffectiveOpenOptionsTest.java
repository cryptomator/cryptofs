package org.cryptomator.cryptofs;

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
import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.nio.file.OpenOption;
import java.util.HashSet;

import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.mockito.junit.MockitoJUnit;
import org.mockito.junit.MockitoRule;

public class EffectiveOpenOptionsTest {

	private ReadonlyFlag falseReadonlyFlag = mock(ReadonlyFlag.class);
	private ReadonlyFlag trueReadonlyFlag = mock(ReadonlyFlag.class);
	private IOException readonlyException = new IOException();

	@Rule
	public ExpectedException thrown = ExpectedException.none();

	@Rule
	public MockitoRule mockitoRule = MockitoJUnit.rule();

	@Before
	public void setup() throws IOException {
		when(falseReadonlyFlag.isSet()).thenReturn(false);
		when(trueReadonlyFlag.isSet()).thenReturn(true);
		doThrow(readonlyException).when(trueReadonlyFlag).assertWritable();
	}

	@Test
	public void testFailIfAppendIsUsedWithRead() throws IOException {
		thrown.expect(IllegalArgumentException.class);

		EffectiveOpenOptions.from(new HashSet<>(asList(APPEND, READ)), falseReadonlyFlag);
	}

	@Test
	public void testFailIfAppendIsUsedWithTruncateExisting() throws IOException {
		thrown.expect(IllegalArgumentException.class);

		EffectiveOpenOptions.from(new HashSet<>(asList(APPEND, TRUNCATE_EXISTING)), falseReadonlyFlag);
	}

	@Test
	public void testUnsupportedOption() throws IOException {
		thrown.expect(IllegalArgumentException.class);

		EffectiveOpenOptions.from(new HashSet<>(asList(new OpenOption() {
		})), falseReadonlyFlag);
	}

	@Test
	public void testEmpty() throws IOException {
		EffectiveOpenOptions inTest = EffectiveOpenOptions.from(new HashSet<>(asList()), falseReadonlyFlag);

		assertFalse(inTest.append());
		assertFalse(inTest.create());
		assertFalse(inTest.createNew());
		assertFalse(inTest.deleteOnClose());
		assertTrue(inTest.readable());
		assertFalse(inTest.syncData());
		assertFalse(inTest.syncDataAndMetadata());
		assertFalse(inTest.truncateExisting());
		assertFalse(inTest.writable());

		assertThat(inTest.createOpenOptionsForEncryptedFile(), containsInAnyOrder(READ, WRITE));
	}

	@Test
	public void testAppend() throws IOException {
		EffectiveOpenOptions inTest = EffectiveOpenOptions.from(new HashSet<>(asList(APPEND)), falseReadonlyFlag);

		assertTrue(inTest.append());
		assertFalse(inTest.create());
		assertFalse(inTest.createNew());
		assertFalse(inTest.deleteOnClose());
		assertFalse(inTest.readable());
		assertFalse(inTest.syncData());
		assertFalse(inTest.syncDataAndMetadata());
		assertFalse(inTest.truncateExisting());
		assertTrue(inTest.writable());

		assertThat(inTest.createOpenOptionsForEncryptedFile(), containsInAnyOrder(READ, WRITE));
	}

	@Test
	public void testCreate() throws IOException {
		EffectiveOpenOptions inTest = EffectiveOpenOptions.from(new HashSet<>(asList(CREATE)), falseReadonlyFlag);

		assertFalse(inTest.append());
		assertFalse(inTest.create());
		assertFalse(inTest.createNew());
		assertFalse(inTest.deleteOnClose());
		assertTrue(inTest.readable());
		assertFalse(inTest.syncData());
		assertFalse(inTest.syncDataAndMetadata());
		assertFalse(inTest.truncateExisting());
		assertFalse(inTest.writable());

		assertThat(inTest.createOpenOptionsForEncryptedFile(), containsInAnyOrder(READ, WRITE));
	}

	@Test
	public void testCreateWithWrite() throws IOException {
		EffectiveOpenOptions inTest = EffectiveOpenOptions.from(new HashSet<>(asList(CREATE, WRITE)), falseReadonlyFlag);

		assertFalse(inTest.append());
		assertTrue(inTest.create());
		assertFalse(inTest.createNew());
		assertFalse(inTest.deleteOnClose());
		assertFalse(inTest.readable());
		assertFalse(inTest.syncData());
		assertFalse(inTest.syncDataAndMetadata());
		assertFalse(inTest.truncateExisting());
		assertTrue(inTest.writable());

		assertThat(inTest.createOpenOptionsForEncryptedFile(), containsInAnyOrder(CREATE, READ, WRITE));
	}

	@Test
	public void testCreateNew() throws IOException {
		EffectiveOpenOptions inTest = EffectiveOpenOptions.from(new HashSet<>(asList(CREATE_NEW)), falseReadonlyFlag);

		assertFalse(inTest.append());
		assertFalse(inTest.create());
		assertFalse(inTest.createNew());
		assertFalse(inTest.deleteOnClose());
		assertTrue(inTest.readable());
		assertFalse(inTest.syncData());
		assertFalse(inTest.syncDataAndMetadata());
		assertFalse(inTest.truncateExisting());
		assertFalse(inTest.writable());

		assertThat(inTest.createOpenOptionsForEncryptedFile(), containsInAnyOrder(READ, WRITE));
	}

	@Test
	public void testCreateNewWithWrite() throws IOException {
		EffectiveOpenOptions inTest = EffectiveOpenOptions.from(new HashSet<>(asList(CREATE_NEW, WRITE)), falseReadonlyFlag);

		assertFalse(inTest.append());
		assertFalse(inTest.create());
		assertTrue(inTest.createNew());
		assertFalse(inTest.deleteOnClose());
		assertFalse(inTest.readable());
		assertFalse(inTest.syncData());
		assertFalse(inTest.syncDataAndMetadata());
		assertFalse(inTest.truncateExisting());
		assertTrue(inTest.writable());

		assertThat(inTest.createOpenOptionsForEncryptedFile(), containsInAnyOrder(CREATE_NEW, READ, WRITE));
	}

	@Test
	public void testCreateNewWithWriteAndCreate() throws IOException {
		EffectiveOpenOptions inTest = EffectiveOpenOptions.from(new HashSet<>(asList(CREATE, CREATE_NEW, WRITE)), falseReadonlyFlag);

		assertFalse(inTest.append());
		assertFalse(inTest.create());
		assertTrue(inTest.createNew());
		assertFalse(inTest.deleteOnClose());
		assertFalse(inTest.readable());
		assertFalse(inTest.syncData());
		assertFalse(inTest.syncDataAndMetadata());
		assertFalse(inTest.truncateExisting());
		assertTrue(inTest.writable());

		assertThat(inTest.createOpenOptionsForEncryptedFile(), containsInAnyOrder(CREATE_NEW, READ, WRITE));
	}

	@Test
	public void testDeleteOnClose() throws IOException {
		EffectiveOpenOptions inTest = EffectiveOpenOptions.from(new HashSet<>(asList(DELETE_ON_CLOSE)), falseReadonlyFlag);

		assertFalse(inTest.append());
		assertFalse(inTest.create());
		assertFalse(inTest.createNew());
		assertTrue(inTest.deleteOnClose());
		assertTrue(inTest.readable());
		assertFalse(inTest.syncData());
		assertFalse(inTest.syncDataAndMetadata());
		assertFalse(inTest.truncateExisting());
		assertFalse(inTest.writable());

		assertThat(inTest.createOpenOptionsForEncryptedFile(), containsInAnyOrder(READ, WRITE, DELETE_ON_CLOSE));
	}

	@Test
	public void testRead() throws IOException {
		EffectiveOpenOptions inTest = EffectiveOpenOptions.from(new HashSet<>(asList(READ)), falseReadonlyFlag);

		assertFalse(inTest.append());
		assertFalse(inTest.create());
		assertFalse(inTest.createNew());
		assertFalse(inTest.deleteOnClose());
		assertTrue(inTest.readable());
		assertFalse(inTest.syncData());
		assertFalse(inTest.syncDataAndMetadata());
		assertFalse(inTest.truncateExisting());
		assertFalse(inTest.writable());

		assertThat(inTest.createOpenOptionsForEncryptedFile(), containsInAnyOrder(READ, WRITE));
	}

	@Test
	public void testSync() throws IOException {
		EffectiveOpenOptions inTest = EffectiveOpenOptions.from(new HashSet<>(asList(SYNC)), falseReadonlyFlag);

		assertFalse(inTest.append());
		assertFalse(inTest.create());
		assertFalse(inTest.createNew());
		assertFalse(inTest.deleteOnClose());
		assertTrue(inTest.readable());
		assertTrue(inTest.syncData());
		assertTrue(inTest.syncDataAndMetadata());
		assertFalse(inTest.truncateExisting());
		assertFalse(inTest.writable());

		assertThat(inTest.createOpenOptionsForEncryptedFile(), containsInAnyOrder(READ, WRITE, SYNC));
	}

	@Test
	public void testDSync() throws IOException {
		EffectiveOpenOptions inTest = EffectiveOpenOptions.from(new HashSet<>(asList(DSYNC)), falseReadonlyFlag);

		assertFalse(inTest.append());
		assertFalse(inTest.create());
		assertFalse(inTest.createNew());
		assertFalse(inTest.deleteOnClose());
		assertTrue(inTest.readable());
		assertTrue(inTest.syncData());
		assertFalse(inTest.syncDataAndMetadata());
		assertFalse(inTest.truncateExisting());
		assertFalse(inTest.writable());

		assertThat(inTest.createOpenOptionsForEncryptedFile(), containsInAnyOrder(READ, WRITE, DSYNC));
	}

	@Test
	public void testTruncateExisting() throws IOException {
		EffectiveOpenOptions inTest = EffectiveOpenOptions.from(new HashSet<>(asList(TRUNCATE_EXISTING)), falseReadonlyFlag);

		assertFalse(inTest.append());
		assertFalse(inTest.create());
		assertFalse(inTest.createNew());
		assertFalse(inTest.deleteOnClose());
		assertTrue(inTest.readable());
		assertFalse(inTest.syncData());
		assertFalse(inTest.syncDataAndMetadata());
		assertFalse(inTest.truncateExisting());
		assertFalse(inTest.writable());

		assertThat(inTest.createOpenOptionsForEncryptedFile(), containsInAnyOrder(READ, WRITE));
	}

	@Test
	public void testWrite() throws IOException {
		EffectiveOpenOptions inTest = EffectiveOpenOptions.from(new HashSet<>(asList(WRITE)), falseReadonlyFlag);

		assertFalse(inTest.append());
		assertFalse(inTest.create());
		assertFalse(inTest.createNew());
		assertFalse(inTest.deleteOnClose());
		assertFalse(inTest.readable());
		assertFalse(inTest.syncData());
		assertFalse(inTest.syncDataAndMetadata());
		assertFalse(inTest.truncateExisting());
		assertTrue(inTest.writable());

		assertThat(inTest.createOpenOptionsForEncryptedFile(), containsInAnyOrder(READ, WRITE));
	}

	@Test
	public void testEmptyWithTrueReadonlyFlag() throws IOException {
		EffectiveOpenOptions inTest = EffectiveOpenOptions.from(new HashSet<>(asList()), trueReadonlyFlag);

		assertFalse(inTest.append());
		assertFalse(inTest.create());
		assertFalse(inTest.createNew());
		assertFalse(inTest.deleteOnClose());
		assertTrue(inTest.readable());
		assertFalse(inTest.syncData());
		assertFalse(inTest.syncDataAndMetadata());
		assertFalse(inTest.truncateExisting());
		assertFalse(inTest.writable());

		assertThat(inTest.createOpenOptionsForEncryptedFile(), containsInAnyOrder(READ));
	}

	@Test
	public void testAppendTrueReadonlyFlag() throws IOException {
		thrown.expect(is(readonlyException));

		EffectiveOpenOptions.from(new HashSet<>(asList(APPEND)), trueReadonlyFlag);
	}

	@Test
	public void testCreateTrueReadonlyFlag() throws IOException {
		EffectiveOpenOptions inTest = EffectiveOpenOptions.from(new HashSet<>(asList(CREATE)), trueReadonlyFlag);

		assertFalse(inTest.append());
		assertFalse(inTest.create());
		assertFalse(inTest.createNew());
		assertFalse(inTest.deleteOnClose());
		assertTrue(inTest.readable());
		assertFalse(inTest.syncData());
		assertFalse(inTest.syncDataAndMetadata());
		assertFalse(inTest.truncateExisting());
		assertFalse(inTest.writable());

		assertThat(inTest.createOpenOptionsForEncryptedFile(), containsInAnyOrder(READ));
	}

	@Test
	public void testCreateWithWriteTrueReadonlyFlag() throws IOException {
		thrown.expect(is(readonlyException));

		EffectiveOpenOptions.from(new HashSet<>(asList(CREATE, WRITE)), trueReadonlyFlag);
	}

	@Test
	public void testCreateNewTrueReadonlyFlag() throws IOException {
		EffectiveOpenOptions inTest = EffectiveOpenOptions.from(new HashSet<>(asList(CREATE_NEW)), trueReadonlyFlag);

		assertFalse(inTest.append());
		assertFalse(inTest.create());
		assertFalse(inTest.createNew());
		assertFalse(inTest.deleteOnClose());
		assertTrue(inTest.readable());
		assertFalse(inTest.syncData());
		assertFalse(inTest.syncDataAndMetadata());
		assertFalse(inTest.truncateExisting());
		assertFalse(inTest.writable());

		assertThat(inTest.createOpenOptionsForEncryptedFile(), containsInAnyOrder(READ));
	}

	@Test
	public void testCreateNewWithWriteTrueReadonlyFlag() throws IOException {
		thrown.expect(is(readonlyException));

		EffectiveOpenOptions.from(new HashSet<>(asList(CREATE_NEW, WRITE)), trueReadonlyFlag);
	}

	@Test
	public void testCreateNewWithWriteAndCreateTrueReadonlyFlag() throws IOException {
		thrown.expect(is(readonlyException));

		EffectiveOpenOptions.from(new HashSet<>(asList(CREATE, CREATE_NEW, WRITE)), trueReadonlyFlag);
	}

	@Test
	public void testDeleteOnCloseTrueReadonlyFlag() throws IOException {
		thrown.expect(is(readonlyException));

		EffectiveOpenOptions.from(new HashSet<>(asList(DELETE_ON_CLOSE)), trueReadonlyFlag);
	}

	@Test
	public void testReadTrueReadonlyFlag() throws IOException {
		EffectiveOpenOptions inTest = EffectiveOpenOptions.from(new HashSet<>(asList(READ)), trueReadonlyFlag);

		assertFalse(inTest.append());
		assertFalse(inTest.create());
		assertFalse(inTest.createNew());
		assertFalse(inTest.deleteOnClose());
		assertTrue(inTest.readable());
		assertFalse(inTest.syncData());
		assertFalse(inTest.syncDataAndMetadata());
		assertFalse(inTest.truncateExisting());
		assertFalse(inTest.writable());

		assertThat(inTest.createOpenOptionsForEncryptedFile(), containsInAnyOrder(READ));
	}

	@Test
	public void testSyncTrueReadonlyFlag() throws IOException {
		EffectiveOpenOptions inTest = EffectiveOpenOptions.from(new HashSet<>(asList(SYNC)), trueReadonlyFlag);

		assertFalse(inTest.append());
		assertFalse(inTest.create());
		assertFalse(inTest.createNew());
		assertFalse(inTest.deleteOnClose());
		assertTrue(inTest.readable());
		assertTrue(inTest.syncData());
		assertTrue(inTest.syncDataAndMetadata());
		assertFalse(inTest.truncateExisting());
		assertFalse(inTest.writable());

		assertThat(inTest.createOpenOptionsForEncryptedFile(), containsInAnyOrder(READ, SYNC));
	}

	@Test
	public void testDSyncTrueReadonlyFlag() throws IOException {
		EffectiveOpenOptions inTest = EffectiveOpenOptions.from(new HashSet<>(asList(DSYNC)), trueReadonlyFlag);

		assertFalse(inTest.append());
		assertFalse(inTest.create());
		assertFalse(inTest.createNew());
		assertFalse(inTest.deleteOnClose());
		assertTrue(inTest.readable());
		assertTrue(inTest.syncData());
		assertFalse(inTest.syncDataAndMetadata());
		assertFalse(inTest.truncateExisting());
		assertFalse(inTest.writable());

		assertThat(inTest.createOpenOptionsForEncryptedFile(), containsInAnyOrder(READ, DSYNC));
	}

	@Test
	public void testTruncateExistingTrueReadonlyFlag() throws IOException {
		EffectiveOpenOptions inTest = EffectiveOpenOptions.from(new HashSet<>(asList(TRUNCATE_EXISTING)), trueReadonlyFlag);

		assertFalse(inTest.append());
		assertFalse(inTest.create());
		assertFalse(inTest.createNew());
		assertFalse(inTest.deleteOnClose());
		assertTrue(inTest.readable());
		assertFalse(inTest.syncData());
		assertFalse(inTest.syncDataAndMetadata());
		assertFalse(inTest.truncateExisting());
		assertFalse(inTest.writable());

		assertThat(inTest.createOpenOptionsForEncryptedFile(), containsInAnyOrder(READ));
	}

	@Test
	public void testWriteTrueReadonlyFlag() throws IOException {
		thrown.expect(is(readonlyException));

		EffectiveOpenOptions.from(new HashSet<>(asList(WRITE)), trueReadonlyFlag);
	}

}
