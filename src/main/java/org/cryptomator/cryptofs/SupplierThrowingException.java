package org.cryptomator.cryptofs;

import java.util.function.Function;
import java.util.function.Supplier;

interface SupplierThrowingException<T,E extends Exception> {

	T get() throws E;
	
	@SuppressWarnings("unchecked")
	default <W extends RuntimeException> Supplier<T> wrapExceptionUsing(Function<E,W> wrapper) {
		return () -> {
			try {
				return get();
			} catch (Exception e) {
				throw wrapper.apply((E)e);
			}
		};
	}
	
}
