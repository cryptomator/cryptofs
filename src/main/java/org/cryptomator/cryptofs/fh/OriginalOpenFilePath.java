package org.cryptomator.cryptofs.fh;

import static java.lang.annotation.RetentionPolicy.RUNTIME;

import java.lang.annotation.Documented;
import java.lang.annotation.Retention;

import jakarta.inject.Qualifier;

/**
 * The Path used to create an OpenCryptoFile
 * @see CurrentOpenFilePath
 */
@Qualifier
@Documented
@Retention(RUNTIME)
@interface OriginalOpenFilePath {
}
