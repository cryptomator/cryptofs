package org.cryptomator.cryptofs.common;

import org.hamcrest.BaseMatcher;
import org.hamcrest.Description;

import java.util.function.Predicate;

public class CustomMatchers {

	public static <T, S extends T> BaseMatcher<T> matching(Class<S> clazz, Predicate<S> predicate, String description) {
		return new BaseMatcher<>() {
			@Override
			public boolean matches(Object actual) {
				if (clazz.isInstance(actual)) {
					return predicate.test((S) actual);
				} else {
					return false;
				}
			}

			@Override
			public void describeTo(Description descr) {
				descr.appendText(description);
			}
		};
	}

}
