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
	int STALE_THRESHOLD_MINUTES = 10;
	int MAX_CLEARTEXT_SIZE_BYTES = 1000; //calculation: Create inUse properties with owner consisting of \u2741.repeat(100) symbols and encode it. Plus an additional buffer for future entries.
}
