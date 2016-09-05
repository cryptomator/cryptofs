package org.cryptomator.cryptofs;

@FunctionalInterface
public interface SupplierThrowingException<T, E extends Exception> {

	T get() throws E;

}