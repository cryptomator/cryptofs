/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptofs;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;

import java.nio.ByteBuffer;

import org.junit.Test;
import org.junit.runner.RunWith;

import de.bechte.junit.runners.context.HierarchicalContextRunner;

@RunWith(HierarchicalContextRunner.class)
public class ByteSourceTest {

	public class FromByteBuffer {

		@Test
		public void testHasRemainingDelegatesToBufferHasRemainingIfTrue() {
			ByteBuffer buffer = ByteBuffer.allocate(1);
			ByteSource inTest = ByteSource.from(buffer);

			assertThat(inTest.hasRemaining(), is(true));
		}

		@Test
		public void testHasRemainingDelegatesToBufferHasRemainingIfFalse() {
			ByteBuffer buffer = ByteBuffer.allocate(0);
			ByteSource inTest = ByteSource.from(buffer);

			assertThat(inTest.hasRemaining(), is(false));
		}

		@Test
		public void testRemainingDelegatesToBuffersRemaining() {
			int expectedResult = 3;
			ByteBuffer buffer = ByteBuffer.allocate(expectedResult);
			ByteSource inTest = ByteSource.from(buffer);

			assertThat(inTest.remaining(), is((long) expectedResult));
		}

		@Test
		public void testCopyToWithLessRemainingInSourceThanInTarget() {
			ByteBuffer sourceBuffer = ByteBuffer.allocate(10);
			sourceBuffer.position(5);
			ByteBuffer targetBuffer = ByteBuffer.allocate(20);
			targetBuffer.position(3);
			ByteSource inTest = ByteSource.from(sourceBuffer);

			inTest.copyTo(targetBuffer);

			assertThat(sourceBuffer.position(), is(10));
			assertThat(sourceBuffer.limit(), is(10));
			assertThat(targetBuffer.position(), is(8));
			assertThat(targetBuffer.limit(), is(20));
		}

		@Test
		public void testCopyToWithLessRemainingInTargetThanInSource() {
			ByteBuffer sourceBuffer = ByteBuffer.allocate(20);
			sourceBuffer.position(3);
			ByteBuffer targetBuffer = ByteBuffer.allocate(10);
			targetBuffer.position(5);
			ByteSource inTest = ByteSource.from(sourceBuffer);

			inTest.copyTo(targetBuffer);

			assertThat(sourceBuffer.position(), is(8));
			assertThat(sourceBuffer.limit(), is(20));
			assertThat(targetBuffer.position(), is(10));
			assertThat(targetBuffer.limit(), is(10));
		}

	}

}
