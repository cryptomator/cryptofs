package org.cryptomator.cryptofs.common;

@FunctionalInterface
public interface SupplierThrowingException<T, E extends Exception> {

	T get() throws E;

}