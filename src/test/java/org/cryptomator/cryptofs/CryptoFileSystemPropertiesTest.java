package org.cryptomator.cryptofs;

import static org.cryptomator.cryptofs.CryptoFileSystemProperties.DEFAULT_MASTERKEY_FILENAME;
import static org.cryptomator.cryptofs.CryptoFileSystemProperties.DEFAULT_PEPPER;
import static org.cryptomator.cryptofs.CryptoFileSystemProperties.PROPERTY_FILESYSTEM_FLAGS;
import static org.cryptomator.cryptofs.CryptoFileSystemProperties.PROPERTY_MASTERKEY_FILENAME;
import static org.cryptomator.cryptofs.CryptoFileSystemProperties.PROPERTY_PASSPHRASE;
import static org.cryptomator.cryptofs.CryptoFileSystemProperties.PROPERTY_PEPPER;
import static org.cryptomator.cryptofs.CryptoFileSystemProperties.cryptoFileSystemProperties;
import static org.cryptomator.cryptofs.CryptoFileSystemProperties.cryptoFileSystemPropertiesFrom;
import static org.hamcrest.CoreMatchers.sameInstance;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertThat;

import java.nio.charset.StandardCharsets;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;

import org.cryptomator.cryptofs.CryptoFileSystemProperties.FileSystemFlags;
import org.hamcrest.Description;
import org.hamcrest.Matcher;
import org.hamcrest.TypeSafeDiagnosingMatcher;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

public class CryptoFileSystemPropertiesTest {

	@Rule
	public ExpectedException thrown = ExpectedException.none();

	@Test
	public void testSetNoPassphrase() {
		thrown.expect(IllegalStateException.class);

		cryptoFileSystemProperties().build();
	}

	@Test
	@SuppressWarnings({"unchecked", "deprecation"})
	public void testSetOnlyPassphrase() {
		String passphrase = "aPassphrase";
		CryptoFileSystemProperties inTest = cryptoFileSystemProperties() //
				.withPassphrase(passphrase) //
				.build();

		assertThat(inTest.passphrase(), is(passphrase));
		assertThat(inTest.masterkeyFilename(), is(DEFAULT_MASTERKEY_FILENAME));
		assertThat(inTest.readonly(), is(false));
		assertThat(inTest.initializeImplicitly(), is(true));
		assertThat(inTest.migrateImplicitly(), is(true));
		assertThat(inTest.entrySet(),
				containsInAnyOrder( //
						anEntry(PROPERTY_PASSPHRASE, passphrase), //
						anEntry(PROPERTY_PEPPER, DEFAULT_PEPPER), //
						anEntry(PROPERTY_MASTERKEY_FILENAME, DEFAULT_MASTERKEY_FILENAME), //
						anEntry(PROPERTY_FILESYSTEM_FLAGS, EnumSet.of(FileSystemFlags.INIT_IMPLICITLY, FileSystemFlags.MIGRATE_IMPLICITLY))));
	}

	@Test
	@SuppressWarnings({"unchecked", "deprecation"})
	public void testSetPassphraseAndReadonlyFlag() {
		String passphrase = "aPassphrase";
		CryptoFileSystemProperties inTest = cryptoFileSystemProperties() //
				.withPassphrase(passphrase) //
				.withReadonlyFlag() //
				.build();

		assertThat(inTest.passphrase(), is(passphrase));
		assertThat(inTest.masterkeyFilename(), is(DEFAULT_MASTERKEY_FILENAME));
		assertThat(inTest.readonly(), is(true));
		assertThat(inTest.initializeImplicitly(), is(false));
		assertThat(inTest.migrateImplicitly(), is(false));
		assertThat(inTest.entrySet(),
				containsInAnyOrder( //
						anEntry(PROPERTY_PASSPHRASE, passphrase), //
						anEntry(PROPERTY_PEPPER, DEFAULT_PEPPER), //
						anEntry(PROPERTY_MASTERKEY_FILENAME, DEFAULT_MASTERKEY_FILENAME), //
						anEntry(PROPERTY_FILESYSTEM_FLAGS, EnumSet.of(FileSystemFlags.READONLY))));
	}

	@Test
	@SuppressWarnings({"unchecked", "deprecation"})
	public void testSetPassphraseAndMasterkeyFilenameAndReadonlyFlag() {
		String passphrase = "aPassphrase";
		String masterkeyFilename = "aMasterkeyFilename";
		CryptoFileSystemProperties inTest = cryptoFileSystemProperties() //
				.withPassphrase(passphrase) //
				.withMasterkeyFilename(masterkeyFilename) //
				.withReadonlyFlag() //
				.build();

		assertThat(inTest.passphrase(), is(passphrase));
		assertThat(inTest.masterkeyFilename(), is(masterkeyFilename));
		assertThat(inTest.readonly(), is(true));
		assertThat(inTest.initializeImplicitly(), is(false));
		assertThat(inTest.migrateImplicitly(), is(false));
		assertThat(inTest.entrySet(),
				containsInAnyOrder( //
						anEntry(PROPERTY_PASSPHRASE, passphrase), //
						anEntry(PROPERTY_PEPPER, DEFAULT_PEPPER), //
						anEntry(PROPERTY_MASTERKEY_FILENAME, masterkeyFilename), //
						anEntry(PROPERTY_FILESYSTEM_FLAGS, EnumSet.of(FileSystemFlags.READONLY))));
	}

	@Test
	@SuppressWarnings({"unchecked"})
	public void testFromMap() {
		Map<String, Object> map = new HashMap<>();
		String passphrase = "aPassphrase";
		byte[] pepper = "aPepper".getBytes(StandardCharsets.US_ASCII);
		String masterkeyFilename = "aMasterkeyFilename";
		map.put(PROPERTY_PASSPHRASE, passphrase);
		map.put(PROPERTY_PEPPER, pepper);
		map.put(PROPERTY_MASTERKEY_FILENAME, masterkeyFilename);
		map.put(PROPERTY_FILESYSTEM_FLAGS, EnumSet.of(FileSystemFlags.READONLY));
		CryptoFileSystemProperties inTest = cryptoFileSystemPropertiesFrom(map).build();

		assertThat(inTest.passphrase(), is(passphrase));
		assertThat(inTest.masterkeyFilename(), is(masterkeyFilename));
		assertThat(inTest.readonly(), is(true));
		assertThat(inTest.initializeImplicitly(), is(false));
		assertThat(inTest.entrySet(),
				containsInAnyOrder( //
						anEntry(PROPERTY_PASSPHRASE, passphrase), //
						anEntry(PROPERTY_PEPPER, pepper), //
						anEntry(PROPERTY_MASTERKEY_FILENAME, masterkeyFilename), //
						anEntry(PROPERTY_FILESYSTEM_FLAGS, EnumSet.of(FileSystemFlags.READONLY))));
	}

	@Test
	@SuppressWarnings("unchecked")
	public void testWrapMapWithTrueReadonly() {
		Map<String, Object> map = new HashMap<>();
		String passphrase = "aPassphrase";
		byte[] pepper = "aPepper".getBytes(StandardCharsets.US_ASCII);
		String masterkeyFilename = "aMasterkeyFilename";
		map.put(PROPERTY_PASSPHRASE, passphrase);
		map.put(PROPERTY_PEPPER, pepper);
		map.put(PROPERTY_MASTERKEY_FILENAME, masterkeyFilename);
		map.put(PROPERTY_FILESYSTEM_FLAGS, EnumSet.of(FileSystemFlags.READONLY));
		CryptoFileSystemProperties inTest = CryptoFileSystemProperties.wrap(map);

		assertThat(inTest.passphrase(), is(passphrase));
		assertThat(inTest.masterkeyFilename(), is(masterkeyFilename));
		assertThat(inTest.readonly(), is(true));
		assertThat(inTest.initializeImplicitly(), is(false));
		assertThat(inTest.entrySet(),
				containsInAnyOrder( //
						anEntry(PROPERTY_PASSPHRASE, passphrase), //
						anEntry(PROPERTY_PEPPER, pepper), //
						anEntry(PROPERTY_MASTERKEY_FILENAME, masterkeyFilename), //
						anEntry(PROPERTY_FILESYSTEM_FLAGS, EnumSet.of(FileSystemFlags.READONLY))));
	}

	@Test
	@SuppressWarnings("unchecked")
	public void testWrapMapWithFalseReadonly() {
		Map<String, Object> map = new HashMap<>();
		String passphrase = "aPassphrase";
		byte[] pepper = "aPepper".getBytes(StandardCharsets.US_ASCII);
		String masterkeyFilename = "aMasterkeyFilename";
		map.put(PROPERTY_PASSPHRASE, passphrase);
		map.put(PROPERTY_PEPPER, pepper);
		map.put(PROPERTY_MASTERKEY_FILENAME, masterkeyFilename);
		map.put(PROPERTY_FILESYSTEM_FLAGS, EnumSet.noneOf(FileSystemFlags.class));
		CryptoFileSystemProperties inTest = CryptoFileSystemProperties.wrap(map);

		assertThat(inTest.passphrase(), is(passphrase));
		assertThat(inTest.masterkeyFilename(), is(masterkeyFilename));
		assertThat(inTest.readonly(), is(false));
		assertThat(inTest.initializeImplicitly(), is(false));
		assertThat(inTest.entrySet(),
				containsInAnyOrder( //
						anEntry(PROPERTY_PASSPHRASE, passphrase), //
						anEntry(PROPERTY_PEPPER, pepper), //
						anEntry(PROPERTY_MASTERKEY_FILENAME, masterkeyFilename), //
						anEntry(PROPERTY_FILESYSTEM_FLAGS, EnumSet.noneOf(FileSystemFlags.class))));
	}

	@Test
	public void testWrapMapWithInvalidFilesystemFlags() {
		thrown.expect(IllegalArgumentException.class);

		Map<String, Object> map = new HashMap<>();
		map.put(PROPERTY_PASSPHRASE, "any");
		map.put(PROPERTY_MASTERKEY_FILENAME, "any");
		map.put(PROPERTY_FILESYSTEM_FLAGS, "invalidType");
		CryptoFileSystemProperties.wrap(map);
	}

	@Test
	public void testWrapMapWithInvalidMasterkeyFilename() {
		thrown.expect(IllegalArgumentException.class);

		Map<String, Object> map = new HashMap<>();
		map.put(PROPERTY_PASSPHRASE, "any");
		map.put(PROPERTY_MASTERKEY_FILENAME, "");
		map.put(PROPERTY_FILESYSTEM_FLAGS, EnumSet.noneOf(FileSystemFlags.class));
		CryptoFileSystemProperties.wrap(map);
	}

	@Test
	public void testWrapMapWithInvalidPassphrase() {
		thrown.expect(IllegalArgumentException.class);

		Map<String, Object> map = new HashMap<>();
		map.put(PROPERTY_PASSPHRASE, new Object());
		map.put(PROPERTY_MASTERKEY_FILENAME, "any");
		map.put(PROPERTY_FILESYSTEM_FLAGS, EnumSet.noneOf(FileSystemFlags.class));
		CryptoFileSystemProperties.wrap(map);
	}

	@Test
	@SuppressWarnings({"unchecked", "deprecation"})
	public void testWrapMapWithoutReadonly() {
		Map<String, Object> map = new HashMap<>();
		String passphrase = "aPassphrase";
		byte[] pepper = "aPepper".getBytes(StandardCharsets.US_ASCII);
		map.put(PROPERTY_PASSPHRASE, passphrase);
		map.put(PROPERTY_PEPPER, pepper);
		CryptoFileSystemProperties inTest = CryptoFileSystemProperties.wrap(map);

		assertThat(inTest.passphrase(), is(passphrase));
		assertThat(inTest.masterkeyFilename(), is(DEFAULT_MASTERKEY_FILENAME));
		assertThat(inTest.readonly(), is(false));
		assertThat(inTest.initializeImplicitly(), is(true));
		assertThat(inTest.migrateImplicitly(), is(true));
		assertThat(inTest.entrySet(),
				containsInAnyOrder( //
						anEntry(PROPERTY_PASSPHRASE, passphrase), //
						anEntry(PROPERTY_PEPPER, pepper), //
						anEntry(PROPERTY_MASTERKEY_FILENAME, DEFAULT_MASTERKEY_FILENAME), //
						anEntry(PROPERTY_FILESYSTEM_FLAGS, EnumSet.of(FileSystemFlags.INIT_IMPLICITLY, FileSystemFlags.MIGRATE_IMPLICITLY))));
	}

	@Test
	public void testWrapMapWithoutPassphrase() {
		thrown.expect(IllegalArgumentException.class);

		CryptoFileSystemProperties.wrap(new HashMap<>());
	}

	@Test
	public void testWrapCryptoFileSystemProperties() {
		CryptoFileSystemProperties inTest = cryptoFileSystemProperties() //
				.withPassphrase("any") //
				.build();

		assertThat(CryptoFileSystemProperties.wrap(inTest), is(sameInstance(inTest)));
	}

	@Test
	public void testMapIsImmutable() {
		thrown.expect(UnsupportedOperationException.class);

		cryptoFileSystemProperties() //
				.withPassphrase("irrelevant") //
				.build() //
				.put("test", "test");
	}

	@Test
	public void testEntrySetIsImmutable() {
		thrown.expect(UnsupportedOperationException.class);

		cryptoFileSystemProperties() //
				.withPassphrase("irrelevant") //
				.build() //
				.entrySet() //
				.add(null);
	}

	@Test
	public void testEntryIsImmutable() {
		thrown.expect(UnsupportedOperationException.class);

		cryptoFileSystemProperties() //
				.withPassphrase("irrelevant") //
				.build() //
				.entrySet() //
				.iterator().next() //
				.setValue(null);
	}

	private <K, V> Matcher<Map.Entry<K, V>> anEntry(K key, V value) {
		return new TypeSafeDiagnosingMatcher<Map.Entry<K, V>>(Map.Entry.class) {
			@Override
			public void describeTo(Description description) {
				description.appendText("an entry ").appendValue(key).appendText(" = ").appendValue(value);
			}

			@Override
			protected boolean matchesSafely(Entry<K, V> item, Description mismatchDescription) {
				if (keyMatches(item.getKey()) && valueMatches(item.getValue())) {
					return true;
				}
				mismatchDescription.appendText("an entry ").appendValue(item.getKey()).appendText(" = ").appendValue(item.getValue());
				return false;
			}

			private boolean keyMatches(K itemKey) {
				return key == null ? itemKey == null : key.equals(itemKey);
			}

			private boolean valueMatches(V itemValue) {
				return value == null ? itemValue == null : value.equals(itemValue);
			}
		};
	}

}
