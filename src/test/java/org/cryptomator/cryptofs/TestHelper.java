package org.cryptomator.cryptofs;

import java.nio.file.Path;

import org.mockito.Mockito;

class TestHelper {

	public static void prepareMockForPathCreation(CryptoFileSystem fileSystemMock, Path pathToVault) {
		CryptoPathFactory cryptoPathFactory = new CryptoPathFactory();
		Mockito.when(fileSystemMock.getPath(Mockito.anyString(), Mockito.anyVararg())).thenAnswer(invocation -> {
			String first = invocation.getArgumentAt(0, String.class);
			if (invocation.getArguments().length == 1) {
				return cryptoPathFactory.getPath(fileSystemMock, first);
			} else {
				String[] more = invocation.getArgumentAt(1, String[].class);
				return cryptoPathFactory.getPath(fileSystemMock, first, more);
			}
		});
		Mockito.when(fileSystemMock.getPathToVault()).thenReturn(pathToVault);
		CryptoPath root = cryptoPathFactory.rootFor(fileSystemMock);
		CryptoPath empty = cryptoPathFactory.emptyFor(fileSystemMock);
		Mockito.when(fileSystemMock.getRootPath()).thenReturn(root);
		Mockito.when(fileSystemMock.getEmptyPath()).thenReturn(empty);
	}

}
