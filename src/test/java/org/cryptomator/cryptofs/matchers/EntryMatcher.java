package org.cryptomator.cryptofs.matchers;

import java.util.Map;

import org.hamcrest.Description;
import org.hamcrest.Matcher;
import org.hamcrest.TypeSafeDiagnosingMatcher;

public class EntryMatcher {

	public static <K, V, T extends Map.Entry<K, V>> TypeSafeDiagnosingMatcher<T> entry(Matcher<K> key, Matcher<V> value) {
		return new TypeSafeDiagnosingMatcher<T>(Map.Entry.class) {
			@Override
			public void describeTo(Description description) {
				description.appendText("an entry with key that ") //
						.appendDescriptionOf(key) //
						.appendText(" and value that ") //
						.appendDescriptionOf(value);
			}

			@Override
			protected boolean matchesSafely(T item, Description mismatchDescription) {
				if (!key.matches(item.getKey())) {
					mismatchDescription.appendText("an entry with key that ");
					key.describeMismatch(item.getKey(), mismatchDescription);
					return false;
				} else if (!value.matches(item.getValue())) {
					mismatchDescription.appendText("an entry with value that ");
					value.describeMismatch(item.getValue(), mismatchDescription);
					return false;
				}
				return true;
			}
		};
	}

}
