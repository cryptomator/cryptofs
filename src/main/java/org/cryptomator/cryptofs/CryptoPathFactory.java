package org.cryptomator.cryptofs;

import java.text.Normalizer;
import java.util.Collections;
import java.util.stream.Stream;

import javax.inject.Inject;

import com.google.common.base.Splitter;

import static java.util.Arrays.stream;
import static java.util.Spliterator.IMMUTABLE;
import static java.util.Spliterator.NONNULL;
import static java.util.Spliterator.ORDERED;
import static java.util.Spliterators.spliteratorUnknownSize;
import static java.util.stream.Collectors.toList;
import static java.util.stream.StreamSupport.stream;
import static org.cryptomator.cryptofs.Constants.SEPARATOR;

@CryptoFileSystemScoped
class CryptoPathFactory {

	private final Symlinks symlinks;

	@Inject
	public CryptoPathFactory(Symlinks symlinks) {
		this.symlinks = symlinks;
	}

	public CryptoPath getPath(CryptoFileSystemImpl fileSystem, String first, String... more) {
		boolean isAbsolute = first.startsWith(SEPARATOR);
		Stream<String> elements = Stream.concat(Stream.of(first), stream(more)).flatMap(this::splitPath).map(this::normalize);
		return new CryptoPath(fileSystem, symlinks, elements.collect(toList()), isAbsolute);
	}

	public CryptoPath emptyFor(CryptoFileSystemImpl fileSystem) {
		return new CryptoPath(fileSystem, symlinks, Collections.emptyList(), false);
	}

	public CryptoPath rootFor(CryptoFileSystemImpl fileSystem) {
		return new CryptoPath(fileSystem, symlinks, Collections.emptyList(), true);
	}

	private Stream<String> splitPath(String path) {
		Iterable<String> tokens = Splitter.on(SEPARATOR).omitEmptyStrings().split(path);
		return stream(spliteratorUnknownSize(tokens.iterator(), ORDERED | IMMUTABLE | NONNULL), false);
	}

	private String normalize(String str) {
		return Normalizer.normalize(str, Normalizer.Form.NFC);
	}

}
