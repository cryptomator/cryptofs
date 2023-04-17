package org.cryptomator.cryptofs.fh;

import org.cryptomator.cryptofs.ch.CleartextFileChannel;

import javax.inject.Inject;
import java.io.IOException;

/**
 * Collector for exceptions that happen during chunk cache invalidation.
 * These exceptions will be rethrown by {@link CleartextFileChannel#force(boolean)}
 */
@OpenFileScoped
public class ExceptionsDuringWrite {

	private final IOException e = new IOException("Exceptions occured while writing");

	@Inject
	public ExceptionsDuringWrite() {
	}

	public synchronized void add(Exception e) {
		this.e.addSuppressed(e);
	}

	public synchronized void throwIfPresent() throws IOException {
		if (e.getSuppressed().length > 0) {
			e.fillInStackTrace();
			throw e;
		}
	}

}
