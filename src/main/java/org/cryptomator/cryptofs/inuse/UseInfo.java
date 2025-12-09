package org.cryptomator.cryptofs.inuse;

import java.time.Instant;

public record UseInfo(String owner, Instant lastUpdated) {

}
