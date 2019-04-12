package org.cryptomator.cryptofs;

import org.junit.jupiter.api.Test;
import org.mockito.InOrder;

import static java.util.Arrays.asList;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;

@SuppressWarnings("unchecked")
public class FinallyUtilTest {

	private FinallyUtil inTest = new FinallyUtil();

	@Test
	public void testFinallyUtilsExecutesAllTasks() throws Exception {
		RunnableThrowingException<Exception> task1 = mock(RunnableThrowingException.class);
		RunnableThrowingException<Exception> task2 = mock(RunnableThrowingException.class);
		RunnableThrowingException<Exception> task3 = mock(RunnableThrowingException.class);

		inTest.guaranteeInvocationOf(task1, task2, task3);

		InOrder inOrder = inOrder(task1, task2, task3);
		inOrder.verify(task1).run();
		inOrder.verify(task2).run();
		inOrder.verify(task3).run();
	}

	@Test
	public void testFinallyUtilsExecutesAllTasksFromIterable() throws Exception {
		RunnableThrowingException<Exception> task1 = mock(RunnableThrowingException.class);
		RunnableThrowingException<Exception> task2 = mock(RunnableThrowingException.class);
		RunnableThrowingException<Exception> task3 = mock(RunnableThrowingException.class);

		inTest.guaranteeInvocationOf(asList(task1, task2, task3));

		InOrder inOrder = inOrder(task1, task2, task3);
		inOrder.verify(task1).run();
		inOrder.verify(task2).run();
		inOrder.verify(task3).run();
	}

	@Test
	public void testFinallyUtilsExecutesAllTasksFromIterator() throws Exception {
		RunnableThrowingException<Exception> task1 = mock(RunnableThrowingException.class);
		RunnableThrowingException<Exception> task2 = mock(RunnableThrowingException.class);
		RunnableThrowingException<Exception> task3 = mock(RunnableThrowingException.class);

		inTest.guaranteeInvocationOf(asList(task1, task2, task3).iterator());

		InOrder inOrder = inOrder(task1, task2, task3);
		inOrder.verify(task1).run();
		inOrder.verify(task2).run();
		inOrder.verify(task3).run();
	}

	@Test
	public void testFinallyUtilsExecutesAllTasksWhenTheyThrowExceptions() throws Exception {
		RunnableThrowingException<Exception> task1 = mock(RunnableThrowingException.class);
		RunnableThrowingException<Exception> task2 = mock(RunnableThrowingException.class);
		RunnableThrowingException<Exception> task3 = mock(RunnableThrowingException.class);
		doThrow(new Exception()).when(task1).run();
		doThrow(new Exception()).when(task2).run();
		doThrow(new Exception()).when(task3).run();

		try {
			inTest.guaranteeInvocationOf(task1, task2, task3);
		} catch (Exception e) {
			// ignore
		}

		InOrder inOrder = inOrder(task1, task2, task3);
		inOrder.verify(task1).run();
		inOrder.verify(task2).run();
		inOrder.verify(task3).run();
	}

}