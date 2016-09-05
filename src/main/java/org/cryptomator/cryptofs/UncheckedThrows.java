package org.cryptomator.cryptofs;

import static java.lang.String.format;

import java.util.Deque;
import java.util.LinkedList;
import java.util.function.Supplier;

/**
 * <p>
 * Implements means to throw checked exceptions crossing method boundaries which do not declare them.
 * <p>
 * The general usage is as follows:
 * <code><pre>
 * return UncheckedThrows.allowUncheckedThrowsOf(IOException.class).from(() ->
 * 	anOperationWithSupplierAsParameter(() ->
 * 		UncheckedThrows.rethrowUnchecked(IOException.class).from(() -> anOperationThrowingIOException());
 * 	)
 * );
 * </pre></code>
 * <p>
 * If rethrowUnchecked is invoked with an exception which is currently not allowed to be thrown unchecked an IllegalStateException will be thrown by rethrowUnchecked.
 * So as long as lines using rethrowUnchecked are covered by tests misuse will not be possible.
 */
class UncheckedThrows {

	private static final ThreadLocal<Deque<Class<?>>> ALLOWED_TO_BE_THROWN_UNCHECKED = ThreadLocal.withInitial(LinkedList::new);

	public static <E extends Exception> UncheckedThrowsAllowanceWithoutAction<E> allowUncheckedThrowsOf(Class<E> type) {
		return new UncheckedThrowsAllowanceWithoutAction<E>() {
			@Override
			public <T> T from(Supplier<T> action) throws E {
				Deque<Class<?>> allowedToBeThrownUnchecked = ALLOWED_TO_BE_THROWN_UNCHECKED.get();
				try {
					allowedToBeThrownUnchecked.addFirst(type);
					return action.get();
				} catch (ExceptionThrownUnchecked e) {
					if (type.isInstance(e.getCause())) {
						throw type.cast(e.getCause());
					}
					throw e;
				} finally {
					allowedToBeThrownUnchecked.removeFirst();
					if (allowedToBeThrownUnchecked.isEmpty()) {
						ALLOWED_TO_BE_THROWN_UNCHECKED.remove();
					}
				}
			}
		};
	};

	public static <E extends Exception> RethrowUncheckedWithoutAction<E> rethrowUnchecked(Class<E> type) {
		assertUncheckdThrowsAllowed(type);
		return new RethrowUncheckedWithoutAction<E>() {
			@Override
			public <T> T from(SupplierThrowingException<T, E> action) {
				try {
					return action.get();
				} catch (Exception e) {
					throw new ExceptionThrownUnchecked(e);
				}
			}
		};
	}

	private static void assertUncheckdThrowsAllowed(Class<? extends Exception> type) {
		Deque<Class<?>> allowedToBeThrownUnchecked = ALLOWED_TO_BE_THROWN_UNCHECKED.get();
		try {
			if (!allowedToBeThrownUnchecked.stream().anyMatch(allowedType -> allowedType.isAssignableFrom(type))) {
				throw new IllegalStateException(format("Unchecked throws of %s not allowed for the current thread", type.getName()));
			}
		} finally {
			if (allowedToBeThrownUnchecked.isEmpty()) {
				ALLOWED_TO_BE_THROWN_UNCHECKED.remove();
			}
		}
	}

	public static interface RethrowUncheckedWithoutAction<E extends Exception> {

		<T> T from(SupplierThrowingException<T, E> action);

		default void from(RunnableThrowingException<E> action) {
			from(() -> {
				action.run();
				return null;
			});
		}

	}

	public static interface UncheckedThrowsAllowanceWithoutAction<E extends Exception> {

		<T> T from(Supplier<T> action) throws E;

		default void from(Runnable action) throws E {
			from(() -> {
				action.run();
				return null;
			});
		}

	}

	public static class ExceptionThrownUnchecked extends RuntimeException {

		private ExceptionThrownUnchecked(Exception thrownUnchecked) {
			super(thrownUnchecked);
		}

	}

}