package org.cryptomator.cryptofs.mocks;

import static java.util.Arrays.asList;

import java.io.IOException;
import java.nio.file.DirectoryStream;
import java.nio.file.Path;
import java.util.Collections;
import java.util.Iterator;

public class DirectoryStreamMock implements DirectoryStream<Path> {

	public static DirectoryStream<Path> empty() {
		return new DirectoryStreamMock(Collections.emptyList());
	}

	public static DirectoryStream<Path> of(Path... paths) {
		return new DirectoryStreamMock(asList(paths));
	}

	public static DirectoryStream<Path> withElementsFrom(Iterable<Path> delegate) {
		return new DirectoryStreamMock(delegate);
	}

	private final Iterable<Path> delegate;
	private boolean open = true;

	private DirectoryStreamMock(Iterable<Path> delegate) {
		this.delegate = delegate;
	}

	@Override
	public Iterator<Path> iterator() {
		assertOpen();
		return delegate.iterator();
	}

	@Override
	public void close() throws IOException {
		open = false;
	}

	private void assertOpen() {
		if (!open) {
			throw new IllegalStateException("Already closed");
		}
	}

}
