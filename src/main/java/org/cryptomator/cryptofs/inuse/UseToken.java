package org.cryptomator.cryptofs.inuse;

import java.io.Closeable;
import java.nio.file.Path;

public sealed interface UseToken extends Closeable permits RealUseToken, UseToken.InitToken {

	UseToken INIT_TOKEN = new InitToken();

	default void moveTo(Path newPath) {}

	default boolean isClosed() {
		return false;
	}

	default void close() {}

	final class InitToken implements UseToken {}

}
