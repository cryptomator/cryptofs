package org.cryptomator.cryptofs;

import static java.util.Arrays.asList;
import static org.cryptomator.cryptofs.FinallyUtils.guaranteeInvocationOf;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;

import org.junit.Rule;
import org.junit.Test;
import org.mockito.InOrder;
import org.mockito.junit.MockitoJUnit;
import org.mockito.junit.MockitoRule;

@SuppressWarnings("unchecked")
public class FinallyUtilsTest {

	@Rule
	public MockitoRule mockitoRule = MockitoJUnit.rule();

	@Test
	public void testFinallyUtilsExecutesAllTasks() throws Exception {
		RunnableThrowingException<Exception> task1 = mock(RunnableThrowingException.class);
		RunnableThrowingException<Exception> task2 = mock(RunnableThrowingException.class);
		RunnableThrowingException<Exception> task3 = mock(RunnableThrowingException.class);

		guaranteeInvocationOf(task1, task2, task3);

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

		guaranteeInvocationOf(asList(task1, task2, task3));

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

		guaranteeInvocationOf(asList(task1, task2, task3).iterator());

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
			guaranteeInvocationOf(task1, task2, task3);
		} catch (Exception e) {
			// ignore
		}

		InOrder inOrder = inOrder(task1, task2, task3);
		inOrder.verify(task1).run();
		inOrder.verify(task2).run();
		inOrder.verify(task3).run();
	}

}