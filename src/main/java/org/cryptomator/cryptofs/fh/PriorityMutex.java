package org.cryptomator.cryptofs.fh;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.locks.LockSupport;

/**
 * Mutex with two (reentrant) states.
 * <p>
 * The mutex hands out redeemable tokens, depending on its state.
 * There are two type of tokens, regular and priority ones.
 * In the regular state, the mutex hands out regular tokens without blocking.
 * On the first priority request, the mutex switches to priority state:
 * * dispensing new regular tokens is blocked
 * * priority requests block until the last dispensed regular token is redeemed.
 * * afterward, all priority requests are handled without blocking
 * <p>
 * If the last handed out priority token is redeemed, the mutex switches back to its regular state, unblocking all regular requests.
 * <p>
 * Based on <a href="https://docs.oracle.com/en/java/javase/21/docs/api/java.base/java/util/concurrent/locks/LockSupport.html">an JDK example</a>
 */
public class PriorityMutex {


	private final AtomicInteger counter = new AtomicInteger(0);
	private final AtomicInteger handedOutRegularTokens = new AtomicInteger(0);
	private final AtomicInteger priorityRequests = new AtomicInteger(0);
	private final Map<Integer, Thread> regularLane = new ConcurrentHashMap<>();
	private final Map<Integer, Thread> fastLane = new ConcurrentHashMap<>();

	/**
	 * Waits until all priority token requests are handled and redeemed and hands out a regular token.
	 */
	public Token dispenseRegular() {
		boolean wasInterrupted = false;
		// publish current thread to regular unparking lane
		var tokenId = counter.incrementAndGet();
		regularLane.put(tokenId, Thread.currentThread());

		//Block while there are not handled or redeemed priority requests/tokens
		while (priorityRequests.get() != 0) {
			LockSupport.park(this);
			// ignore interrupts while waiting
			if (Thread.interrupted()) wasInterrupted = true;
		}
		handedOutRegularTokens.incrementAndGet();
		regularLane.remove(tokenId);
		// ensure correct interrupt status on return
		if (wasInterrupted) Thread.currentThread().interrupt();
		return () -> {
			handedOutRegularTokens.decrementAndGet();
			redeem();
		};
	}

	/**
	 * Waits until all handed-out regular tokens are redeemed and hands out a priority token.
	 */
	public Token dispensePriority() {
		priorityRequests.incrementAndGet();
		boolean wasInterrupted = false;
		// publish current thread to priority unparking lane
		var tokenId = counter.incrementAndGet();
		fastLane.put(tokenId, Thread.currentThread());

		//Block while there are not redeemed regular tokens
		while (handedOutRegularTokens.get() != 0) {
			LockSupport.park(this);
			// ignore interrupts while waiting
			if (Thread.interrupted()) wasInterrupted = true;
		}

		fastLane.remove(tokenId);
		// ensure correct interrupt status on return
		if (wasInterrupted) Thread.currentThread().interrupt();
		return () -> {
			priorityRequests.decrementAndGet();
			redeem();
		};
	}

	private void redeem() {
		if (priorityRequests.get() != 0) {
			fastLane.forEach((id, thread) -> LockSupport.unpark(thread));
		} else {
			regularLane.forEach((id, thread) -> LockSupport.unpark(thread));
		}
	}

	static {
		// Reduce the risk of "lost unpark" due to classloading
		Class<?> ensureLoaded = LockSupport.class;
	}

	@FunctionalInterface
	interface Token extends AutoCloseable {

		void redeem();

		default void close() {
			redeem();
		}
	}

	;

}