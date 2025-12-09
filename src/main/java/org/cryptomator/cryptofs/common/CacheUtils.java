package org.cryptomator.cryptofs.common;

import com.github.benmanes.caffeine.cache.Cache;

import java.io.IOException;
import java.io.UncheckedIOException;

public abstract class CacheUtils {

	private CacheUtils() {}

	/**
	 * Helper function for caches with IO loading functions.
	 * <p>
	 * This method implements the famous workaround for (checked) IOExceptions in cache loading functions:
	 * {@code
	 *  try {
	 *      cache.get(key, k -> {
	 *          try {
	 *              return functionThrowingIOException(k)
	 *          } catch (IOException e) {
	 *              throw UncheckedIOException(e);
	 *          }
	 *      }
	 *  } catch (UncheckedIOException e) {
	 *      throw e.getCause()
	 *  }
	 * }
	 *
	 * @param key The key to load from the cache
	 * @param cache The cache to get the value
	 * @param loadFunction The load function which can throw an IOException
	 * @return the cached value or null, if the loading function returns it.
	 * @param <K> The type of keys used in the cache
	 * @param <V> the type of values used in the cache
	 * @throws IOException if the loading function throws an IOException
	 */
	public static <K, V> V getWithIOWrapped(K key, Cache<K, V> cache, IOFunction<K, V> loadFunction) throws IOException {
		try {
			return cache.get(key, k -> {
				try {
					return loadFunction.apply(k);
				} catch (IOException e) {
					throw new UncheckedIOException(e);
				}
			});
		} catch (UncheckedIOException e) {
			throw e.getCause();
		}
	}

	@FunctionalInterface
	public interface IOFunction<T, R> {

		R apply(T t) throws IOException;
	}
}
