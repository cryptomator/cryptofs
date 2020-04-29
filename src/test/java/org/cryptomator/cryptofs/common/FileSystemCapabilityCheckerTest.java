package org.cryptomator.cryptofs.common;

import org.cryptomator.cryptofs.mocks.DirectoryStreamMock;
import org.cryptomator.cryptofs.mocks.SeekableByteChannelMock;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.mockito.Mockito;

import java.io.IOException;
import java.nio.file.DirectoryIteratorException;
import java.nio.file.FileSystem;
import java.nio.file.Path;
import java.nio.file.spi.FileSystemProvider;
import java.util.Collections;

class FileSystemCapabilityCheckerTest {
	
	@Nested
	@TestInstance(TestInstance.Lifecycle.PER_CLASS)
	class PathLengthLimits {
		
		private Path pathToVault = Mockito.mock(Path.class);
		private Path cDir = Mockito.mock(Path.class);
		private Path fillerDir = Mockito.mock(Path.class);
		private Path nnnDir = Mockito.mock(Path.class);
		private FileSystem fileSystem = Mockito.mock(FileSystem.class);
		private FileSystemProvider fileSystemProvider = Mockito.mock(FileSystemProvider.class);
		
		@BeforeEach
		public void setup() throws IOException {
			Mockito.when(pathToVault.getFileSystem()).thenReturn(fileSystem);
			Mockito.when(fileSystem.provider()).thenReturn(fileSystemProvider);
			Mockito.when(pathToVault.resolve("c")).thenReturn(cDir);
			Mockito.when(cDir.resolve(Mockito.anyString())).thenReturn(fillerDir);
			Mockito.when(fillerDir.resolve(Mockito.anyString())).thenReturn(nnnDir);
			Mockito.when(fillerDir.getFileSystem()).thenReturn(fileSystem);
			Mockito.when(nnnDir.getFileSystem()).thenReturn(fileSystem);
			Mockito.when(fileSystemProvider.newDirectoryStream(Mockito.eq(fillerDir), Mockito.any())).thenReturn(DirectoryStreamMock.empty());
		}

		@Test
		@DisplayName("determineSupportedFileNameLength() on unrestricted file system")
		public void testUnlimitedLength() throws IOException {
			Mockito.when(fillerDir.resolve(Mockito.anyString())).then(invocation -> {
				String checkDirStr = invocation.getArgument(0);
				Path checkDirMock = Mockito.mock(Path.class, checkDirStr);
				Mockito.when(checkDirMock.getFileSystem()).thenReturn(fileSystem);
				Mockito.when(checkDirMock.resolve(Mockito.anyString())).then(invocation2 -> {
					String checkFileStr = invocation.getArgument(0);
					Path checkFileMock = Mockito.mock(Path.class, checkFileStr);
					Mockito.when(checkFileMock.getFileSystem()).thenReturn(fileSystem);
					Mockito.when(fileSystemProvider.newByteChannel(Mockito.eq(checkFileMock), Mockito.any()))
							.thenReturn(new SeekableByteChannelMock(0));
					return checkFileMock;
				});
				Mockito.when(fileSystemProvider.newDirectoryStream(Mockito.eq(checkDirMock), Mockito.any())).thenReturn(DirectoryStreamMock.empty());
				return checkDirMock;
			});

			int determinedLimit = new FileSystemCapabilityChecker().determineSupportedFileNameLength(pathToVault);

			Assertions.assertEquals(220, determinedLimit);
		}

		@Test
		@DisplayName("determineSupportedFileNameLength() on restricted file system that allows file creation but fails in dir listing (Win/WebDAV)")
		public void testLimitedLengthDuringDirListing() throws IOException {
			int limit = 150;
			Mockito.when(fillerDir.resolve(Mockito.anyString())).then(invocation -> {
				String checkDirStr = invocation.getArgument(0);
				Path checkDirMock = Mockito.mock(Path.class, checkDirStr);
				Mockito.when(checkDirMock.getFileSystem()).thenReturn(fileSystem);
				Mockito.when(checkDirMock.resolve(Mockito.anyString())).then(invocation2 -> {
					String checkFileStr = invocation.getArgument(0);
					Path checkFileMock = Mockito.mock(Path.class, checkFileStr);
					Mockito.when(checkFileMock.getFileSystem()).thenReturn(fileSystem);
					Mockito.when(fileSystemProvider.newByteChannel(Mockito.eq(checkFileMock), Mockito.any()))
							.thenReturn(new SeekableByteChannelMock(0));
					return checkFileMock;
				});
				Mockito.when(fileSystemProvider.newDirectoryStream(Mockito.eq(checkDirMock), Mockito.any())).then(invocation3 -> {
					Iterable<Path> iterable = Mockito.mock(Iterable.class);
					if (Integer.valueOf(checkDirStr) > limit) {
						Mockito.when(iterable.iterator()).thenThrow(new DirectoryIteratorException(new IOException("path too long")));
					} else {
						Mockito.when(iterable.iterator()).thenReturn(Collections.emptyIterator());
					}
					return DirectoryStreamMock.withElementsFrom(iterable);
				});
				return checkDirMock;
			});

			int determinedLimit = new FileSystemCapabilityChecker().determineSupportedFileNameLength(pathToVault);
			
			Assertions.assertEquals(limit, determinedLimit);
		}

		@Test
		@DisplayName("determineSupportedFileNameLength() on restricted file system that fails during file creation (Linux/eCryptfs)")
		public void testLimitedLengthDuringFileCreation() throws IOException {
			int limit = 150;
			Mockito.when(fillerDir.resolve(Mockito.anyString())).then(invocation -> {
				String checkDirStr = invocation.getArgument(0);
				Path checkDirMock = Mockito.mock(Path.class, checkDirStr);
				Mockito.when(checkDirMock.getFileSystem()).thenReturn(fileSystem);
				Mockito.when(checkDirMock.resolve(Mockito.anyString())).then(invocation2 -> {
					String checkFileStr = invocation.getArgument(0);
					Path checkFileMock = Mockito.mock(Path.class, checkFileStr);
					Mockito.when(checkFileMock.getFileSystem()).thenReturn(fileSystem);
					if (Integer.valueOf(checkDirStr) > limit) {
						Mockito.when(fileSystemProvider.newByteChannel(Mockito.eq(checkFileMock), Mockito.any()))
								.thenThrow(new IOException("name too long"));
					} else {
						Mockito.when(fileSystemProvider.newByteChannel(Mockito.eq(checkFileMock), Mockito.any()))
								.thenReturn(new SeekableByteChannelMock(0));
					}
					return checkFileMock;
				});
				Mockito.when(fileSystemProvider.newDirectoryStream(Mockito.eq(checkDirMock), Mockito.any())).thenReturn(DirectoryStreamMock.empty());
				return checkDirMock;
			});

			int determinedLimit = new FileSystemCapabilityChecker().determineSupportedFileNameLength(pathToVault);

			Assertions.assertEquals(limit, determinedLimit);
		}
		
	}

}