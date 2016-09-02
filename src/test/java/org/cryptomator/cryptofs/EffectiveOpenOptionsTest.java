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
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;

import java.nio.file.OpenOption;
import java.util.HashSet;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

public class EffectiveOpenOptionsTest {

	@Rule
	public ExpectedException thrown = ExpectedException.none();

	@Test
	public void testFailIfAppendIsUsedWithRead() {
		thrown.expect(IllegalArgumentException.class);

		EffectiveOpenOptions.from(new HashSet<>(asList(APPEND, READ)));
	}

	@Test
	public void testFailIfAppendIsUsedWithTruncateExisting() {
		thrown.expect(IllegalArgumentException.class);

		EffectiveOpenOptions.from(new HashSet<>(asList(APPEND, TRUNCATE_EXISTING)));
	}

	@Test
	public void testUnsupportedOption() {
		thrown.expect(IllegalArgumentException.class);

		EffectiveOpenOptions.from(new HashSet<>(asList(new OpenOption() {
		})));
	}

	@Test
	public void testEmpty() {
		EffectiveOpenOptions inTest = EffectiveOpenOptions.from(new HashSet<>(asList()));

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
	public void testAppend() {
		EffectiveOpenOptions inTest = EffectiveOpenOptions.from(new HashSet<>(asList(APPEND)));

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
	public void testCreate() {
		EffectiveOpenOptions inTest = EffectiveOpenOptions.from(new HashSet<>(asList(CREATE)));

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
	public void testCreateWithWrite() {
		EffectiveOpenOptions inTest = EffectiveOpenOptions.from(new HashSet<>(asList(CREATE, WRITE)));

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
	public void testCreateNew() {
		EffectiveOpenOptions inTest = EffectiveOpenOptions.from(new HashSet<>(asList(CREATE_NEW)));

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
	public void testCreateNewWithWrite() {
		EffectiveOpenOptions inTest = EffectiveOpenOptions.from(new HashSet<>(asList(CREATE_NEW, WRITE)));

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
	public void testCreateNewWithWriteAndCreate() {
		EffectiveOpenOptions inTest = EffectiveOpenOptions.from(new HashSet<>(asList(CREATE, CREATE_NEW, WRITE)));

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
	public void testDeleteOnClose() {
		EffectiveOpenOptions inTest = EffectiveOpenOptions.from(new HashSet<>(asList(DELETE_ON_CLOSE)));

		assertFalse(inTest.append());
		assertFalse(inTest.create());
		assertFalse(inTest.createNew());
		assertTrue(inTest.deleteOnClose());
		assertTrue(inTest.readable());
		assertFalse(inTest.syncData());
		assertFalse(inTest.syncDataAndMetadata());
		assertFalse(inTest.truncateExisting());
		assertFalse(inTest.writable());

		assertThat(inTest.createOpenOptionsForEncryptedFile(), containsInAnyOrder(READ, DELETE_ON_CLOSE));
	}

	@Test
	public void testRead() {
		EffectiveOpenOptions inTest = EffectiveOpenOptions.from(new HashSet<>(asList(READ)));

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
	public void testSync() {
		EffectiveOpenOptions inTest = EffectiveOpenOptions.from(new HashSet<>(asList(SYNC)));

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
	public void testDSync() {
		EffectiveOpenOptions inTest = EffectiveOpenOptions.from(new HashSet<>(asList(DSYNC)));

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
	public void testTruncateExisting() {
		EffectiveOpenOptions inTest = EffectiveOpenOptions.from(new HashSet<>(asList(TRUNCATE_EXISTING)));

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
	public void testWrite() {
		EffectiveOpenOptions inTest = EffectiveOpenOptions.from(new HashSet<>(asList(WRITE)));

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

}
