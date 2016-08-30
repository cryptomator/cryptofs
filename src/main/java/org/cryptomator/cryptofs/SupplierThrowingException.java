/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptofs;

import java.util.function.Function;
import java.util.function.Supplier;

interface SupplierThrowingException<T,E extends Exception> {

	T get() throws E;
	
	@SuppressWarnings("unchecked")
	default <W extends RuntimeException> Supplier<T> wrapExceptionUsing(Function<E,W> wrapper) {
		return () -> {
			try {
				return get();
			} catch (Exception e) {
				throw wrapper.apply((E)e);
			}
		};
	}
	
}
