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
import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;

import org.cryptomator.cryptofs.OpenCounter.OpenState;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

public class OpenCounterTest {

	@Rule
	public ExpectedException thrown = ExpectedException.none();
	
	private OpenCounter inTest = new OpenCounter();
	
	@Test
	public void testNewOpenCounterReturnsJustOpenedOnOpen() {
		OpenState result = inTest.countOpen();
		
		assertThat(result, is(JUST_OPENED));
	}
	
	@Test
	public void testOpenOpenCounterReturnsWasOpenOnOpen() {
		inTest.countOpen();
		OpenState result = inTest.countOpen();
		
		assertThat(result, is(WAS_OPEN));
	}
	
	@Test
	public void testAlreadyClosedOpenCounterReturnsAlreadyClosedOnOpen() {
		inTest.countOpen();
		inTest.countClose();
		OpenState result = inTest.countOpen();
		
		assertThat(result, is(ALREADY_CLOSED));
	}
	
	@Test
	public void testAlreadyClosedOpenCounterThrowsIllegalStateExceptionWhenClosedAfterOpened() {
		inTest.countOpen();
		inTest.countClose();
		inTest.countOpen();
		
		thrown.expect(IllegalStateException.class);
		
		inTest.countClose();
	}
	
	@Test
	public void testNewOpenCounterThrowsIllegalStateExceptionWhenClosed() {
		thrown.expect(IllegalStateException.class);
		
		inTest.countClose();
	}
	
	@Test
	public void testOpenCounterThrowsIllegalStateExceptionWhenClosedMoreOftenThanOpened() {
		inTest.countOpen();
		inTest.countOpen();
		inTest.countClose();
		inTest.countOpen();
		inTest.countClose();
		inTest.countClose();
		
		thrown.expect(IllegalStateException.class);
		
		inTest.countClose();
	}
	
}
