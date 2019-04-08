package org.cryptomator.cryptofs;

import javax.inject.Inject;
import javax.inject.Singleton;
import java.util.Arrays;
import java.util.Iterator;
import java.util.stream.Stream;
import java.util.stream.StreamSupport;

@Singleton
class FinallyUtil {

	@Inject
	public FinallyUtil() {
	}

	@SuppressWarnings({"unchecked"})
	public <E extends Exception> void guaranteeInvocationOf(RunnableThrowingException<? extends E>... tasks) throws E {
		this.<E>guaranteeInvocationOf(Arrays.stream(tasks));
	}

	public <E extends Exception> void guaranteeInvocationOf(Iterable<RunnableThrowingException<? extends E>> tasks) throws E {
		this.<E>guaranteeInvocationOf(StreamSupport.stream(tasks.spliterator(), false));
	}

	@SuppressWarnings({"unchecked"})
	public <E extends Exception> void guaranteeInvocationOf(Stream<RunnableThrowingException<? extends E>> tasks) throws E {
		this.<E>guaranteeInvocationOf(tasks.map(t -> (RunnableThrowingException<E>) t).iterator());
	}

	@SuppressWarnings("unchecked")
	public <E extends Exception> void guaranteeInvocationOf(Iterator<RunnableThrowingException<E>> tasks) throws E {
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
