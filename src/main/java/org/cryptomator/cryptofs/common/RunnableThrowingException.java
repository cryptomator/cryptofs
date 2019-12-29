package org.cryptomator.cryptofs.common;

@FunctionalInterface
public interface RunnableThrowingException<E extends Exception> {

	void run() throws E;

}
