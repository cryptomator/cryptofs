package org.cryptomator.cryptofs.common;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.condition.EnabledOnOs;
import org.junit.jupiter.api.condition.OS;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.DosFileAttributeView;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.Random;
import java.util.stream.Stream;

public class BackupHelperTest {

	@EnabledOnOs({OS.LINUX, OS.MAC})
	@ParameterizedTest
	@MethodSource("createRandomBytes")
	public void testBackupFilePosix(byte[] contents, @TempDir Path tmp) throws IOException {
		Path originalFile = tmp.resolve("original");
		Files.write(originalFile, contents);
		
		Path backupFile = BackupHelper.attemptBackup(originalFile);
		Assertions.assertArrayEquals(contents, Files.readAllBytes(backupFile));
		
		Files.setPosixFilePermissions(backupFile, PosixFilePermissions.fromString("r--r--r--"));
		Path backupFile2 = BackupHelper.attemptBackup(originalFile);
		Assertions.assertEquals(backupFile, backupFile2);
	}

	@EnabledOnOs({OS.WINDOWS})
	@ParameterizedTest
	@MethodSource("createRandomBytes")
	public void testBackupFileWin(byte[] contents, @TempDir Path tmp) throws IOException {
		Path originalFile = tmp.resolve("original");
		Files.write(originalFile, contents);

		Path backupFile = BackupHelper.attemptBackup(originalFile);
		Assertions.assertArrayEquals(contents, Files.readAllBytes(backupFile));
		
		Files.getFileAttributeView(backupFile, DosFileAttributeView.class).setReadOnly(true);
		Path backupFile2 = BackupHelper.attemptBackup(originalFile);
		Assertions.assertEquals(backupFile, backupFile2);
	}

	public static Stream<byte[]> createRandomBytes() {
		Random rnd = new Random(42L);
		return Stream.generate(() -> {
			byte[] bytes = new byte[100];
			rnd.nextBytes(bytes);
			return bytes;
		}).limit(10);
	}

}