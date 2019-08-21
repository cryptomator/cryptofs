package org.cryptomator.cryptofs.migration.v7;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.mockito.Mockito;

import java.nio.file.Path;

public class FilePathMigrationTest {

	private Path vaultRoot = Mockito.mock(Path.class, "vaultRoot");

	@ParameterizedTest(name = "getOldCanonicalNameWithoutTypePrefix() expected to be {1} for {0}")
	@CsvSource({
			"ORSXG5A=,ORSXG5A=",
			"0ORSXG5A=,ORSXG5A=",
			"1SORSXG5A=,ORSXG5A=",
	})
	public void testGetOldCanonicalNameWithoutTypePrefix(String oldCanonicalName, boolean expectedResult) {
		FilePathMigration migration = new FilePathMigration(vaultRoot, oldCanonicalName);

		Assertions.assertEquals(expectedResult, migration.getOldCanonicalNameWithoutTypePrefix());
	}

	@ParameterizedTest(name = "getNewInflatedName() expected to be {1} for {0}")
	@CsvSource({
			"ORSXG5A=,dGVzdA==.c9r",
			"0ORSXG5A=,dGVzdA==.c9r",
			"1SORSXG5A=,dGVzdA==.c9r",
	})
	public void testGetNewInflatedName(String oldCanonicalName, boolean expectedResult) {
		FilePathMigration migration = new FilePathMigration(vaultRoot, oldCanonicalName);

		Assertions.assertEquals(expectedResult, migration.getNewInflatedName());
	}

	@ParameterizedTest(name = "getNewInflatedName() expected to be {1} for {0}")
	@CsvSource({
			"ORSXG5A=,dGVzdA==.c9r",
			"ORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSQ====,dGVzdCB0ZXN0IHRlc3QgdGVzdCB0ZXN0IHRlc3QgdGVzdCB0ZXN0IHRlc3QgdGVzdCB0ZXN0IHRlc3QgdGVzdCB0ZXN0IHRlc3QgdGVzdCB0ZXN0IHRlc3QgdGVzdCB0ZXN0IHRlc3QgdGVzdCB0ZXN0IHRlc3QgdGVzdCB0ZXN0IHRlc3QgdGVzdCB0ZXN0IHRlc3QgdGVzdCB0ZXN0IHRl.c9r",
			"ORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG5BAORSXG===,df4c6d4b7623b22309470bb5a0055cff44b66805.c9s",
	})
	public void testGetNewDeflatedName(String oldCanonicalName, boolean expectedResult) {
		FilePathMigration migration = new FilePathMigration(vaultRoot, oldCanonicalName);

		Assertions.assertEquals(expectedResult, migration.getNewDeflatedName());
	}
	
	@ParameterizedTest(name = "isDirectory() expected to be {1} for {0}")
	@CsvSource({
			"ORSXG5A=,false",
			"0ORSXG5A=,true",
			"1SORSXG5A=,false",
	})
	public void testIsDirectory(String oldCanonicalName, boolean expectedResult) {
		FilePathMigration migration = new FilePathMigration(vaultRoot, oldCanonicalName);
		
		Assertions.assertEquals(expectedResult, migration.isDirectory());
	}

	@ParameterizedTest(name = "isSymlink() expected to be {1} for {0}")
	@CsvSource({
			"ORSXG5A=,false",
			"0ORSXG5A=,false",
			"1SORSXG5A=,true",
	})
	public void testIsSymlink(String oldCanonicalName, boolean expectedResult) {
		FilePathMigration migration = new FilePathMigration(vaultRoot, oldCanonicalName);

		Assertions.assertEquals(expectedResult, migration.isSymlink());
	}
	
}
