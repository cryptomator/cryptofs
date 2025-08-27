package org.cryptomator.cryptofs.inuse;

import org.cryptomator.cryptofs.fh.FileAlreadyInUseException;
import org.cryptomator.cryptofs.fh.UseToken;

import java.io.IOException;
import java.nio.file.Path;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentMap;
import java.util.function.BiFunction;

public class IgnoringInUseManager implements InUseManager {

	private static final ConcurrentMap<Path, UseToken> useTokens = new FakeConcurrentMap();

	@Override
	public boolean isInUse(Path ciphertextPath) throws IOException, IllegalArgumentException {
		return false;
	}

	@Override
	public UseToken use(Path ciphertextPath) throws FileAlreadyInUseException {
		return UseToken.createInvalid(ciphertextPath, useTokens);
	}

	private static class FakeConcurrentMap implements ConcurrentMap<Path, UseToken> {

		@Override
		public UseToken compute(Path key,
						  BiFunction<? super Path, ? super UseToken, ? extends UseToken> remappingFunction) {
			return null;
		}

		@Override
		public int size() {
			return 0;
		}

		@Override
		public boolean isEmpty() {
			return false;
		}

		@Override
		public boolean containsKey(Object key) {
			return false;
		}

		@Override
		public boolean containsValue(Object value) {
			return false;
		}

		@Override
		public UseToken get(Object key) {
			return null;
		}

		@Override
		public UseToken put(Path key, UseToken value) {
			return null;
		}

		@Override
		public UseToken remove(Object key) {
			return null;
		}

		@Override
		public void putAll(Map<? extends Path, ? extends UseToken> m) {

		}

		@Override
		public void clear() {

		}

		@Override
		public Set<Path> keySet() {
			return Set.of();
		}

		@Override
		public Collection<UseToken> values() {
			return List.of();
		}

		@Override
		public Set<Entry<Path, UseToken>> entrySet() {
			return Set.of();
		}

		@Override
		public UseToken putIfAbsent(Path key, UseToken value) {
			return null;
		}

		@Override
		public boolean remove(Object key, Object value) {
			return false;
		}

		@Override
		public boolean replace(Path key, UseToken oldValue, UseToken newValue) {
			return false;
		}

		@Override
		public UseToken replace(Path key, UseToken value) {
			return null;
		}
	}
}
