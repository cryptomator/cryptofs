package org.cryptomator.cryptofs;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import javax.inject.Inject;

@PerOpenFile
class ExceptionsDuringWrite {

	private final List<IOException> exceptions = new ArrayList<>(); // todo handle / deliver exception

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
