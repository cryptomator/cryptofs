package org.cryptomator.cryptofs.matchers;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.Matchers.greaterThanOrEqualTo;

import java.nio.ByteBuffer;
import java.util.function.Function;

import org.hamcrest.FeatureMatcher;
import org.hamcrest.Matcher;

public class ByteBufferMatcher {

	public static Matcher<ByteBuffer> hasAtLeastRemaining(int remaining) {
		return matcher("bytes remaining", greaterThanOrEqualTo(remaining), ByteBuffer::remaining);
	}

	public static Matcher<ByteBuffer> hasRemaining(int remaining) {
		return matcher("bytes remaining", is(remaining), ByteBuffer::remaining);
	}

	public static Matcher<ByteBuffer> contains(ByteBuffer data) {
		byte[] arrayData = new byte[data.remaining()];
		data.get(arrayData);
		return contains(arrayData);
	}

	public static Matcher<ByteBuffer> contains(byte[] data) {
		return matcher("remaining data", is(data), buffer -> {
			int position = buffer.position();
			byte[] remaining = new byte[buffer.remaining()];
			buffer.get(remaining);
			buffer.position(position);
			return remaining;
		});
	}

	private static <T, V> Matcher<T> matcher(String name, Matcher<? super V> subMatcher, Function<T, V> getter) {
		return new FeatureMatcher<T, V>(subMatcher, name, name) {
			@Override
			protected V featureValueOf(T actual) {
				return getter.apply(actual);
			}
		};
	}

}
