package org.cryptomator.cryptofs;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;

import java.nio.ByteBuffer;

import org.junit.Test;

public class ByteBufferByteSourceTest {
	
	@Test
	public void testHasRemainingDelegatesToBufferHasRemainingIfTrue() {
		ByteBuffer buffer = ByteBuffer.allocate(10);
		ByteSource inTest = new ByteBufferByteSource(buffer);
		
		assertThat(inTest.hasRemaining(), is(true));
	}
	
	@Test
	public void testHasRemainingDelegatesToBufferHasRemainingIfFalse() {
		ByteBuffer buffer = ByteBuffer.allocate(0);
		ByteSource inTest = new ByteBufferByteSource(buffer);
		
		assertThat(inTest.hasRemaining(), is(false));
	}
	

	
	@Test
	public void testRemainingDelegatesToBuffersRemaining() {
		int expectedResult = 3721;
		ByteBuffer buffer = ByteBuffer.allocate(expectedResult);
		ByteSource inTest = new ByteBufferByteSource(buffer);
		
		assertThat(inTest.remaining(), is((long)expectedResult));
	}
	
	@Test
	public void testCopyToWithLessRemainingInSourceThanInTarget() {
		ByteBuffer sourceBuffer = ByteBuffer.allocate(100);
		sourceBuffer.position(50);
		ByteBuffer targetBuffer = ByteBuffer.allocate(200);
		targetBuffer.position(30);
		ByteSource inTest = new ByteBufferByteSource(sourceBuffer);
		
		inTest.copyTo(targetBuffer);
		
		assertThat(sourceBuffer.position(), is(100));
		assertThat(sourceBuffer.limit(), is(100));
		assertThat(targetBuffer.position(), is(80));
		assertThat(targetBuffer.limit(), is(200));
	}
	
	@Test
	public void testCopyToWithLessRemainingInTargetThanInSource() {
		ByteBuffer sourceBuffer = ByteBuffer.allocate(200);
		sourceBuffer.position(30);
		ByteBuffer targetBuffer = ByteBuffer.allocate(100);
		targetBuffer.position(50);
		ByteSource inTest = new ByteBufferByteSource(sourceBuffer);
		
		inTest.copyTo(targetBuffer);
		
		assertThat(sourceBuffer.position(), is(80));
		assertThat(sourceBuffer.limit(), is(200));
		assertThat(targetBuffer.position(), is(100));
		assertThat(targetBuffer.limit(), is(100));
	}
	
}
