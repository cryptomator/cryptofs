package org.cryptomator.cryptofs;

import static java.util.Arrays.stream;
import static java.util.Spliterator.IMMUTABLE;
import static java.util.Spliterator.NONNULL;
import static java.util.Spliterator.ORDERED;
import static java.util.Spliterators.spliteratorUnknownSize;
import static java.util.stream.Collectors.toList;
import static java.util.stream.StreamSupport.stream;
import static org.cryptomator.cryptofs.Constants.SEPARATOR;

import java.util.Collections;
import java.util.Iterator;
import java.util.StringTokenizer;
import java.util.stream.Stream;

import javax.inject.Inject;

@PerProvider
class CryptoPathFactory {

	@Inject
	public CryptoPathFactory() {
	}

	public CryptoPath getPath(CryptoFileSystemImpl fileSystem, String first, String... more) {
		boolean isAbsolute = first.startsWith(SEPARATOR);
		Stream<String> elements = Stream.concat(splitPath(first), stream(more).flatMap(this::splitPath));
		return new CryptoPath(fileSystem, elements.collect(toList()), isAbsolute);
	}

	public CryptoPath emptyFor(CryptoFileSystemImpl fileSystem) {
		return new CryptoPath(fileSystem, Collections.emptyList(), false);
	}

	public CryptoPath rootFor(CryptoFileSystemImpl fileSystem) {
		return new CryptoPath(fileSystem, Collections.emptyList(), true);
	}

	private Stream<String> splitPath(String path) {
		StringTokenizer tokenizer = new StringTokenizer(path, SEPARATOR);
		Iterator<String> iterator = new Iterator<String>() {
			@Override
			public boolean hasNext() {
				return tokenizer.hasMoreTokens();
			}

			@Override
			public String next() {
				return tokenizer.nextToken();
			}
		};
		return stream(spliteratorUnknownSize(iterator, ORDERED | IMMUTABLE | NONNULL), false);
	}

}
