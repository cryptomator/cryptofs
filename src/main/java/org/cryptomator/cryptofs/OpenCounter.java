/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptofs;

import static org.cryptomator.cryptofs.OpenCounter.OpenState.ALREADY_CLOSED;
import static org.cryptomator.cryptofs.OpenCounter.OpenState.JUST_OPENED;
import static org.cryptomator.cryptofs.OpenCounter.OpenState.WAS_OPEN;

import java.util.concurrent.atomic.AtomicLong;

/**
 * <p>Counter for pairwise open/close operations.
 * <p>After an OpenCounter has finally been closed (openCount == closeCount && openCount > 0) no open operation will succeed.
 */
class OpenCounter {
	
	private final AtomicLong count = new AtomicLong(0);
	
	public OpenState countOpen() {
		long value = count.getAndIncrement();
		if (value > 0) {
			return WAS_OPEN;
		} else if (value == 0) {
			return JUST_OPENED;
		} else {
			return ALREADY_CLOSED;
		}
	}
	
	public boolean countClose() {
		return count.updateAndGet(this::countClose) <= 0;
	}
	
	private long countClose(long openCount) {
		if (openCount < 1) {
			throw new IllegalStateException("Close without corresponding open");
		} else {
			long newValue = openCount - 1;
			if (newValue == 0) {
				return Long.MIN_VALUE;
			} else {
				return newValue;
			}
		}
	}
	
	public static enum OpenState {
		JUST_OPENED,
		WAS_OPEN,
		ALREADY_CLOSED
	}

}
