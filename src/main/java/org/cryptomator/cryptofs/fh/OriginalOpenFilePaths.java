package org.cryptomator.cryptofs.fh;

import static java.lang.annotation.RetentionPolicy.RUNTIME;

import java.lang.annotation.Documented;
import java.lang.annotation.Retention;

import javax.inject.Qualifier;

/**
 * The Path used to create an OpenCryptoFile
 * @see CurrentOpenFilePaths
 */
@Qualifier
@Documented
@Retention(RUNTIME)
@interface OriginalOpenFilePaths {
}
