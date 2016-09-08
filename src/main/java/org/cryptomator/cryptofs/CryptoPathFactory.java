package org.cryptomator.cryptofs;

import static java.lang.Math.max;
import static java.util.Arrays.stream;
import static java.util.Spliterator.IMMUTABLE;
import static java.util.Spliterator.NONNULL;
import static java.util.Spliterators.spliteratorUnknownSize;
import static java.util.stream.StreamSupport.stream;
import static org.cryptomator.cryptofs.Constants.SEPARATOR;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.StringTokenizer;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import javax.inject.Inject;

@PerProvider
class CryptoPathFactory {

	@Inject
	public CryptoPathFactory() {
	}

	public CryptoPath getPath(CryptoFileSystem fileSystem, String first, String... more) {
		List<String> elements = new ArrayList<>(max(10, 1 + more.length));
		splitPath(first).forEach(elements::add);
		stream(more).flatMap(this::splitPath).collect(Collectors.toList()).forEach(elements::add);
		boolean isAbsolute = first.startsWith(SEPARATOR);
		return new CryptoPath(fileSystem, elements, isAbsolute);
	}

	public CryptoPath emptyFor(CryptoFileSystem fileSystem) {
		return new CryptoPath(fileSystem, Collections.emptyList(), false);
	}

	public CryptoPath rootFor(CryptoFileSystem fileSystem) {
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
		return stream(spliteratorUnknownSize(iterator, IMMUTABLE & NONNULL), false);
	}

}
