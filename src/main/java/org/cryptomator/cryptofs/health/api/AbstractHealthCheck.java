package org.cryptomator.cryptofs.health.api;

import org.cryptomator.cryptofs.VaultConfig;
import org.cryptomator.cryptolib.api.Cryptor;
import org.cryptomator.cryptolib.api.Masterkey;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.file.Path;
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

public abstract class AbstractHealthCheck implements HealthCheck {

	private static final Logger LOG = LoggerFactory.getLogger(AbstractHealthCheck.class);

	private final AtomicBoolean cancelled = new AtomicBoolean();
	private Future<?> task;

	@Override
	public final Stream<DiagnosticResult> check(Path pathToVault, VaultConfig config, Masterkey masterkey, Cryptor cryptor, ExecutorService executor) {
		ResultSpliterator resultSpliterator = new ResultSpliterator();

		task = executor.submit(() -> {
			try {
				check(pathToVault, config, masterkey, cryptor, resultSpliterator);
			} catch (CancellationException e) {
				assert cancelled.get();
				LOG.debug("{} cancelled.", identifier());
			} finally {
				resultSpliterator.end();
			}
		});

		return StreamSupport.stream(resultSpliterator, false);
	}

	/**
	 * Checks the vault at the given path.
	 *
	 * @param pathToVault     Path to the vault's root directory
	 * @param config          The parsed and verified vault config
	 * @param masterkey       The masterkey
	 * @param cryptor         A cryptor initialized for this vault
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

	private class ResultSpliterator extends Spliterators.AbstractSpliterator<DiagnosticResult> implements Consumer<DiagnosticResult> {

		private static final DiagnosticResult POISON = new PoisonResult();

		private final TransferQueue<DiagnosticResult> queue = new LinkedTransferQueue<>();

		public ResultSpliterator() {
			super(Long.MAX_VALUE, DISTINCT | NONNULL | IMMUTABLE);
		}

		@Override
		public boolean tryAdvance(Consumer<? super DiagnosticResult> action) {
			try {
				var result = queue.take();
				if (result == POISON) {
					return false;
				} else {
					action.accept(result);
					return true;
				}
			} catch (InterruptedException e) {
				Thread.currentThread().interrupt();
				return false;
			}
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
				throw new CancellationException();
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
