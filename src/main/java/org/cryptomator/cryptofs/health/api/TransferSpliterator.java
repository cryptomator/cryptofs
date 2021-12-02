package org.cryptomator.cryptofs.health.api;

import com.google.common.base.Preconditions;

import java.util.Objects;
import java.util.Spliterators;
import java.util.concurrent.LinkedTransferQueue;
import java.util.concurrent.TransferQueue;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Consumer;

/**
 * A concurrent spliterator that only {@link java.util.Spliterator#tryAdvance(Consumer) advances} by transferring
 * elements it {@link Consumer#accept(Object) consumes}. Consumption blocks if the spliterator is not advanced.
 * <p>
 * Once no futher elements are expected, this spliterator <b>must</b> be {@link #close() closed}, otherwise it'll
 * wait indefinitely.
 *
 * @param <T> the type of elements consumed and returned
 */
class TransferSpliterator<T> extends Spliterators.AbstractSpliterator<T> implements Consumer<T>, AutoCloseable {

	private final TransferQueue<T> queue = new LinkedTransferQueue<>();
	private final AtomicBoolean poisoned = new AtomicBoolean();
	private final T poison;

	/**
	 * @param poison A unique value that must be distinct to every single value expected to be transferred.
	 */
	public TransferSpliterator(T poison) {
		super(Long.MAX_VALUE, DISTINCT | NONNULL | IMMUTABLE);
		this.poison = Objects.requireNonNull(poison);
	}

	@Override
	public boolean tryAdvance(Consumer<? super T> action) {
		try {
			var element = queue.take();
			if (element == poison) {
				return false;
			} else {
				action.accept(element);
				return true;
			}
		} catch (InterruptedException e) {
			Thread.currentThread().interrupt();
			return false;
		}
	}

	/**
	 * Transfers the value to consuming thread. Blocks until transfer is complete or thread is interrupted.
	 * @param value The value to transfer
	 * @throws TransferClosedException If the transfer has been closed or this thread is interrupted while waiting for the consuming side.
	 */
	@Override
	public void accept(T value) throws TransferClosedException {
		Preconditions.checkArgument(value != poison, "must not feed poison");
		if (poisoned.get()) {
			throw new TransferClosedException();
		}
		try {
			queue.transfer(value);
		} catch (InterruptedException e) {
			Thread.currentThread().interrupt();
			throw new TransferClosedException();
		}
	}

	@Override
	public void close() {
		poisoned.set(true);
		boolean accepted = queue.offer(poison);
		assert accepted : "queue is unbounded, offer must succeed";
	}

	/**
	 * Thrown if an attempt is made to {@link #accept(Object) transfer} further elements after the TransferSpliterator
	 * has been closed.
	 */
	public static class TransferClosedException extends IllegalStateException {}

}
