package org.cryptomator.cryptofs.inuse;

import java.io.Closeable;
import java.nio.file.Path;

public sealed interface UseToken extends Closeable permits RealUseToken, UseToken.InitToken, UseToken.ClosedToken {

	UseToken INIT_TOKEN = new InitToken();
	UseToken CLOSED_TOKEN = new ClosedToken();

	default void moveTo(Path newCiphertextPath) {}

	default boolean isClosed() {
		return false;
	}

	default void close() {}

	record InitToken() implements UseToken {}

	record ClosedToken() implements UseToken {

		@Override
		public boolean isClosed() {
			return true;
		}

	}

	//fields
	String LASTUPDATED_KEY = "lastUpdated";
	String OWNER_KEY = "owner";
}
