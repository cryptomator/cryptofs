package org.cryptomator.cryptofs.fh;

import org.cryptomator.cryptofs.ch.CleartextFileChannel;

import javax.inject.Inject;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/**
 * Collector for exceptions that happen during chunk cache invalidation.
 * These exceptions will be rethrown by {@link CleartextFileChannel#force(boolean)}
 */
@OpenFileScoped
public class ExceptionsDuringWrite {

	private final List<IOException> exceptions = new ArrayList<>();

	@Inject
	public ExceptionsDuringWrite() {
	}

	public synchronized void add(IOException e) {
		exceptions.add(e);
	}

	public synchronized void throwIfPresent() throws IOException {
		if (!exceptions.isEmpty()) {
			IOException e = new IOException("Exceptions occured while writing");
			exceptions.forEach(e::addSuppressed);
			throw e;
		}
	}

}
