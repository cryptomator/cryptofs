package org.cryptomator.cryptofs;

import static java.lang.annotation.RetentionPolicy.RUNTIME;

import java.lang.annotation.Documented;
import java.lang.annotation.Retention;

import jakarta.inject.Scope;

@Scope
@Documented
@Retention(RUNTIME)
public @interface CryptoFileSystemScoped {
}
