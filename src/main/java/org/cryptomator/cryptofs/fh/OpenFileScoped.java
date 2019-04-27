package org.cryptomator.cryptofs.fh;

import javax.inject.Scope;
import java.lang.annotation.Documented;
import java.lang.annotation.Retention;

import static java.lang.annotation.RetentionPolicy.RUNTIME;

/**
 * An OpenFile is {@link OpenCryptoFiles#getOrCreate(java.nio.file.Path) created} with the sole purpose of opening a FileChannel.
 * <p>
 * When the last active file channel is closed, the OpenFile is closed. I.e. it is strictly required for anyone creating an OpenFile to get, use and close a FileChannel.
 */
@Scope
@Documented
@Retention(RUNTIME)
@interface OpenFileScoped {
}
