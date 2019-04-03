package org.cryptomator.cryptofs;

import java.util.Arrays;
import java.util.Objects;
import java.util.stream.Stream;

/**
 * Functions used from commons-lang
 */
public final class ArrayUtils {

	public static boolean contains(Object[] array, Object objectToFind) {
		return Arrays.stream(Objects.requireNonNull(array)).anyMatch(Objects.requireNonNull(objectToFind)::equals);
	}

	public static <S, T extends S> Stream<T> filterByType(S[] array, Class<T> type) {
		return Arrays.stream(array).filter(type::isInstance).map(type::cast);
	}

	public static <T> Stream<T> without(T[] array, T obj) {
		return Arrays.stream(array).filter(x -> !obj.equals(x));
	}

	public static <T> Stream<T> with(T[] array, T obj) {
		return Stream.concat(Arrays.stream(array), Stream.of(obj));
	}

}
