package org.cryptomator.cryptofs.fh;

import jakarta.inject.Qualifier;
import java.lang.annotation.Documented;
import java.lang.annotation.Retention;

import static java.lang.annotation.RetentionPolicy.RUNTIME;

/**
 * The current Path of an OpenCryptoFile.
 * @see OriginalOpenFilePath
 */
@Qualifier
@Documented
@Retention(RUNTIME)
public @interface CurrentOpenFilePath {
}
