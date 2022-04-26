/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptofs.ch;

import org.hamcrest.MatcherAssert;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;
import java.util.Arrays;

import static org.hamcrest.CoreMatchers.is;

public class ByteSourceTest {

	@Nested
	public class FromByteBuffer {

		@Test
		public void testHasRemainingDelegatesToBufferHasRemainingIfTrue() {
			ByteBuffer buffer = ByteBuffer.allocate(1);
			ByteSource inTest = ByteSource.from(buffer);

			MatcherAssert.assertThat(inTest.hasRemaining(), is(true));
		}

		@Test
		public void testHasRemainingDelegatesToBufferHasRemainingIfFalse() {
			ByteBuffer buffer = ByteBuffer.allocate(0);
			ByteSource inTest = ByteSource.from(buffer);

			MatcherAssert.assertThat(inTest.hasRemaining(), is(false));
		}

		@Test
		public void testRemainingDelegatesToBuffersRemaining() {
			int expectedResult = 3;
			ByteBuffer buffer = ByteBuffer.allocate(expectedResult);
			ByteSource inTest = ByteSource.from(buffer);

			MatcherAssert.assertThat(inTest.remaining(), is((long) expectedResult));
		}

		@Test
		public void testCopyToWithLessRemainingInSourceThanInTarget() {
			ByteBuffer sourceBuffer = ByteBuffer.allocate(10);
			sourceBuffer.position(5);
			ByteBuffer targetBuffer = ByteBuffer.allocate(20);
			targetBuffer.position(3);
			ByteSource inTest = ByteSource.from(sourceBuffer);

			inTest.copyTo(targetBuffer);

			MatcherAssert.assertThat(sourceBuffer.position(), is(10));
			MatcherAssert.assertThat(sourceBuffer.limit(), is(10));
			MatcherAssert.assertThat(targetBuffer.position(), is(8));
			MatcherAssert.assertThat(targetBuffer.limit(), is(20));
		}

		@Test
		public void testCopyToWithLessRemainingInTargetThanInSource() {
			ByteBuffer sourceBuffer = ByteBuffer.allocate(20);
			sourceBuffer.position(3);
			ByteBuffer targetBuffer = ByteBuffer.allocate(10);
			targetBuffer.position(5);
			ByteSource inTest = ByteSource.from(sourceBuffer);

			inTest.copyTo(targetBuffer);

			MatcherAssert.assertThat(sourceBuffer.position(), is(8));
			MatcherAssert.assertThat(sourceBuffer.limit(), is(20));
			MatcherAssert.assertThat(targetBuffer.position(), is(10));
			MatcherAssert.assertThat(targetBuffer.limit(), is(10));
		}

	}

	@Nested
	public class RepeatingZeros {

		@Test
		public void testRemainingCombinesZerosWithBuffer() {
			ByteBuffer buffer = ByteBuffer.wrap(new byte[]{(byte) 0xFF});
			ByteSource inTest = ByteSource.repeatingZeroes(41).followedBy(buffer);

			Assertions.assertTrue(inTest.hasRemaining());
			Assertions.assertEquals(42, inTest.remaining());
		}

		@Test
		public void testCopyToWritesZeros() {
			ByteBuffer buffer = ByteBuffer.wrap(new byte[]{(byte) 0x77});
			ByteSource inTest = ByteSource.repeatingZeroes(41).followedBy(buffer);
			byte[] target = new byte[50];
			Arrays.fill(target, (byte) 0xFF); // pre-fill target to check whether data gets zero'ed

			inTest.copyTo(ByteBuffer.wrap(target));

			Assertions.assertArrayEquals(new byte[41], Arrays.copyOf(target, 41));
			Assertions.assertEquals(0x77, target[41]);
		}

		@Test
		public void testCopyToWritesLotsOfZeros() {
			ByteBuffer buffer = ByteBuffer.wrap(new byte[]{(byte) 0x77});
			ByteSource inTest = ByteSource.repeatingZeroes(9999).followedBy(buffer);
			byte[] target = new byte[10_000];
			Arrays.fill(target, (byte) 0xFF); // pre-fill target to check whether data gets zero'ed

			inTest.copyTo(ByteBuffer.wrap(target));

			Assertions.assertArrayEquals(new byte[9999], Arrays.copyOf(target, 9999));
			Assertions.assertEquals(0x77, target[9999]);
		}

	}

}
