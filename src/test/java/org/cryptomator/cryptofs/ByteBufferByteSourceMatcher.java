package org.cryptomator.cryptofs;

import java.nio.ByteBuffer;

import org.hamcrest.Description;
import org.hamcrest.Matcher;
import org.hamcrest.TypeSafeDiagnosingMatcher;

public class ByteBufferByteSourceMatcher {

	public static Matcher<ByteBufferByteSource> aByteBufferByteSourceWrapping(ByteBuffer buffer) {
		return new TypeSafeDiagnosingMatcher<ByteBufferByteSource>(ByteBufferByteSource.class) {
			@Override
			public void describeTo(Description description) {
				description //
					.appendText("a ByteBufferByteSource wrapping ") //
					.appendValue(buffer);
			}
			@Override
			protected boolean matchesSafely(ByteBufferByteSource item, Description mismatchDescription) {
				if (buffer.equals(item.getBuffer())) {
					return true;
				} else {
					mismatchDescription //
						.appendText("a ByteBufferByteSource wrapping ") //
						.appendValue(item.getBuffer());
					return false;
				}
			}
		};
	}
	
}
