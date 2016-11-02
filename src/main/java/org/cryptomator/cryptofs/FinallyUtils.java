package org.cryptomator.cryptofs;

import static java.util.Arrays.asList;

import java.util.Iterator;

class FinallyUtils {

	@SafeVarargs
	@SuppressWarnings({"rawtypes", "unchecked"})
	public static <E extends Exception> void guaranteeInvocationOf(RunnableThrowingException<? extends E>... tasks) throws E {
		guaranteeInvocationOf((Iterator) asList(tasks).iterator());
	}

	@SuppressWarnings({"rawtypes", "unchecked"})
	public static <E extends Exception> void guaranteeInvocationOf(Iterable<RunnableThrowingException<? extends E>> tasks) throws E {
		guaranteeInvocationOf((Iterator) tasks.iterator());
	}

	@SuppressWarnings("unchecked")
	public static <E extends Exception> void guaranteeInvocationOf(Iterator<RunnableThrowingException<E>> tasks) throws E {
		if (tasks.hasNext()) {
			RunnableThrowingException<E> next = tasks.next();
			try {
				next.run();
			} catch (Exception e) {
				throw (E) e;
			} finally {
				guaranteeInvocationOf(tasks);
			}
		}
	}

}
