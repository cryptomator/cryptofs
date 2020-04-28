package org.cryptomator.cryptofs.migration.api;

import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

public abstract class SimpleMigrationContinuationListener implements MigrationContinuationListener {

	private final Lock lock = new ReentrantLock();
	private final Condition waitForResult = lock.newCondition();
	private final AtomicReference<ContinuationResult> atomicResult = new AtomicReference<>();

	/**
	 * Invoked when the migration requires action.
	 * <p>
	 * Usually you want to ask for user feedback on the UI thread at this point.
	 *
	 * @param event The migration event that occurred
	 * @apiNote This method is called from the migrator thread
	 */
	public abstract void migrationHaltedDueToEvent(ContinuationEvent event);

	/**
	 * Continues the migration on its original thread with the desired ContinuationResult.
	 *
	 * @param result How to proceed with the migration
	 * @apiNote This method can be called from any thread.
	 */
	public final void continueMigrationWithResult(ContinuationResult result) {
		lock.lock();
		try {
			atomicResult.set(result);
			waitForResult.signal();
		} finally {
			lock.unlock();
		}
	}

	@Override
	public final ContinuationResult continueMigrationOnEvent(ContinuationEvent event) {
		migrationHaltedDueToEvent(event);
		lock.lock();
		try {
			waitForResult.await();
			return atomicResult.get();
		} catch (InterruptedException e) {
			Thread.interrupted();
			return ContinuationResult.CANCEL;
		} finally {
			lock.unlock();
		}
	}
}
