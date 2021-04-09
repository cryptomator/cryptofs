package org.cryptomator.cryptofs.health.api;

import org.cryptomator.cryptofs.VaultConfig;
import org.cryptomator.cryptolib.api.Cryptor;
import org.cryptomator.cryptolib.api.Masterkey;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.file.Path;
import java.util.Iterator;
import java.util.Spliterators;
import java.util.concurrent.CancellationException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Future;
import java.util.concurrent.LinkedTransferQueue;
import java.util.concurrent.TransferQueue;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Consumer;
import java.util.stream.Stream;
import java.util.stream.StreamSupport;

import static java.util.Spliterator.DISTINCT;
import static java.util.Spliterator.IMMUTABLE;
import static java.util.Spliterator.NONNULL;

public abstract class AbstractHealthCheck implements HealthCheck {

	private static final Logger LOG = LoggerFactory.getLogger(AbstractHealthCheck.class);

	private final AtomicBoolean cancelled = new AtomicBoolean();
	private Future<?> task;

	@Override
	public final Stream<DiagnosticResult> check(Path pathToVault, VaultConfig config, Masterkey masterkey, Cryptor cryptor, ExecutorService executor) {
		ResultIterator resultIterator = new ResultIterator();

		task = executor.submit(() -> {
			try {
				check(pathToVault, config, masterkey, cryptor, resultIterator);
			} catch (CancellationException e) {
				assert cancelled.get();
				LOG.info("{} cancelled.", identifier());
			} finally {
				resultIterator.end();
			}
		});

		return StreamSupport.stream(Spliterators.spliteratorUnknownSize(resultIterator, DISTINCT | NONNULL | IMMUTABLE), false);
	}

	/**
	 * Checks the vault at the given path.
	 *
	 * @param pathToVault Path to the vault's root directory
	 * @param config The parsed and verified vault config
	 * @param masterkey The masterkey
	 * @param cryptor A cryptor initialized for this vault
	 * @param resultCollector A callback collecting results. Invoking this method may block until the result is processed.
	 */
	protected abstract void check(Path pathToVault, VaultConfig config, Masterkey masterkey, Cryptor cryptor, Consumer<DiagnosticResult> resultCollector);

	@Override
	public void cancel() {
		if (task != null) {
			cancelled.set(true);
			task.cancel(true);
		}
	}

	private class ResultIterator implements Iterator<DiagnosticResult>, Consumer<DiagnosticResult> {

		private static final DiagnosticResult POISON = new PoisonResult();
		private final TransferQueue<DiagnosticResult> queue = new LinkedTransferQueue<>();
		private DiagnosticResult currentElement;

		@Override
		public boolean hasNext() {
			if (cancelled.get()) {
				return false;
			}
			try {
				this.currentElement = queue.take();
				return currentElement != POISON;
			} catch (InterruptedException e) {
				Thread.currentThread().interrupt();
				return false; // prevent further iteration
			}
		}

		@Override
		public DiagnosticResult next() {
			return currentElement;
		}

		@Override
		public void accept(DiagnosticResult diagnosticResult) throws CancellationException {
			if (cancelled.get()) {
				throw new CancellationException();
			}
			try {
				queue.transfer(diagnosticResult);
			} catch (InterruptedException e) {
				Thread.currentThread().interrupt();
				if (cancelled.get()) {
					throw new CancellationException();
				}
			}
		}

		public void end() {
			queue.offer(POISON);
		}

	}

	private static record PoisonResult() implements DiagnosticResult {
		@Override
		public Severity getServerity() {
			return null;
		}
	}

}
