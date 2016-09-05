package org.cryptomator.cryptofs;

@FunctionalInterface
interface RunnableThrowingException<E extends Exception> {

	void run() throws E;

}
