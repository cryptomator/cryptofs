package org.cryptomator.cryptofs;

import static org.cryptomator.cryptofs.CryptoFileSystemProperties.PROPERTY_PASSPHRASE;
import static org.cryptomator.cryptofs.CryptoFileSystemProperties.PROPERTY_READONLY;
import static org.cryptomator.cryptofs.CryptoFileSystemProperties.cryptoFileSystemProperties;
import static org.cryptomator.cryptofs.CryptoFileSystemProperties.cryptoFileSystemPropertiesFrom;
import static org.hamcrest.CoreMatchers.sameInstance;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertThat;

import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;

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
	@SuppressWarnings("unchecked")
	public void testSetOnlyPassphrase() {
		String passphrase = "aPassphrase";
		CryptoFileSystemProperties inTest = cryptoFileSystemProperties() //
				.withPassphrase(passphrase) //
				.build();

		assertThat(inTest.passphrase(), is(passphrase));
		assertThat(inTest.readonly(), is(false));
		assertThat(inTest.entrySet(),
				containsInAnyOrder( //
						anEntry(PROPERTY_PASSPHRASE, passphrase), //
						anEntry(PROPERTY_READONLY, false)));
	}

	@Test
	@SuppressWarnings("unchecked")
	public void testSetPassphraseAndReadonlyFlag() {
		String passphrase = "aPassphrase";
		CryptoFileSystemProperties inTest = cryptoFileSystemProperties() //
				.withPassphrase(passphrase) //
				.withReadonlyFlag() //
				.build();

		assertThat(inTest.passphrase(), is(passphrase));
		assertThat(inTest.readonly(), is(true));
		assertThat(inTest.entrySet(),
				containsInAnyOrder( //
						anEntry(PROPERTY_PASSPHRASE, passphrase), //
						anEntry(PROPERTY_READONLY, true)));
	}

	@Test
	@SuppressWarnings("unchecked")
	public void testFromMap() {
		Map<String, Object> map = new HashMap<>();
		String passphrase = "aPassphrase";
		map.put(PROPERTY_PASSPHRASE, passphrase);
		map.put(PROPERTY_READONLY, true);
		CryptoFileSystemProperties inTest = cryptoFileSystemPropertiesFrom(map).build();

		assertThat(inTest.passphrase(), is(passphrase));
		assertThat(inTest.readonly(), is(true));
		assertThat(inTest.entrySet(),
				containsInAnyOrder( //
						anEntry(PROPERTY_PASSPHRASE, passphrase), //
						anEntry(PROPERTY_READONLY, true)));
	}

	@Test
	@SuppressWarnings("unchecked")
	public void testWrapMapWithTrueReadonly() {
		Map<String, Object> map = new HashMap<>();
		String passphrase = "aPassphrase";
		map.put(PROPERTY_PASSPHRASE, passphrase);
		map.put(PROPERTY_READONLY, true);
		CryptoFileSystemProperties inTest = CryptoFileSystemProperties.wrap(map);

		assertThat(inTest.passphrase(), is(passphrase));
		assertThat(inTest.readonly(), is(true));
		assertThat(inTest.entrySet(),
				containsInAnyOrder( //
						anEntry(PROPERTY_PASSPHRASE, passphrase), //
						anEntry(PROPERTY_READONLY, true)));
	}

	@Test
	@SuppressWarnings("unchecked")
	public void testWrapMapWithFalseReadonly() {
		Map<String, Object> map = new HashMap<>();
		String passphrase = "aPassphrase";
		map.put(PROPERTY_PASSPHRASE, passphrase);
		map.put(PROPERTY_READONLY, false);
		CryptoFileSystemProperties inTest = CryptoFileSystemProperties.wrap(map);

		assertThat(inTest.passphrase(), is(passphrase));
		assertThat(inTest.readonly(), is(false));
		assertThat(inTest.entrySet(),
				containsInAnyOrder( //
						anEntry(PROPERTY_PASSPHRASE, passphrase), //
						anEntry(PROPERTY_READONLY, false)));
	}

	@Test
	public void testWrapMapWithInvalidReadonly() {
		thrown.expect(IllegalArgumentException.class);

		Map<String, Object> map = new HashMap<>();
		map.put(PROPERTY_PASSPHRASE, "any");
		map.put(PROPERTY_READONLY, 1);
		CryptoFileSystemProperties.wrap(map);
	}

	@Test
	public void testWrapMapWithInvalidPassphrase() {
		thrown.expect(IllegalArgumentException.class);

		Map<String, Object> map = new HashMap<>();
		map.put(PROPERTY_PASSPHRASE, new Object());
		map.put(PROPERTY_READONLY, false);
		CryptoFileSystemProperties.wrap(map);
	}

	@Test
	@SuppressWarnings("unchecked")
	public void testWrapMapWithoutReadonly() {
		Map<String, Object> map = new HashMap<>();
		String passphrase = "aPassphrase";
		map.put(PROPERTY_PASSPHRASE, passphrase);
		CryptoFileSystemProperties inTest = CryptoFileSystemProperties.wrap(map);

		assertThat(inTest.passphrase(), is(passphrase));
		assertThat(inTest.readonly(), is(false));
		assertThat(inTest.entrySet(),
				containsInAnyOrder( //
						anEntry(PROPERTY_PASSPHRASE, passphrase), //
						anEntry(PROPERTY_READONLY, false)));
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
