/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptofs;

import com.google.common.io.MoreFiles;
import com.google.common.jimfs.Configuration;
import com.google.common.jimfs.Jimfs;
import org.cryptomator.cryptofs.ch.CleartextFileChannel;
import org.cryptomator.cryptolib.api.InvalidPassphraseException;
import org.hamcrest.MatcherAssert;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestMethodOrder;

import java.io.IOException;
import java.net.URI;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.ReadableByteChannel;
import java.nio.channels.WritableByteChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileSystem;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.BasicFileAttributeView;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.EnumSet;
import java.util.List;

import static java.nio.file.Files.readAllBytes;
import static java.nio.file.StandardCopyOption.REPLACE_EXISTING;
import static org.cryptomator.cryptofs.CryptoFileSystemProperties.cryptoFileSystemProperties;
import static org.hamcrest.Matchers.is;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
public class CryptoFileSystemProviderIntegrationTest {

	private FileSystem tmpFs;
	private Path pathToVault1;
	private Path pathToVault2;
	private Path masterkeyFile1;
	private Path masterkeyFile2;
	private FileSystem fs1;
	private FileSystem fs2;

	@BeforeAll
	public void setup() throws IOException {
		tmpFs = Jimfs.newFileSystem(Configuration.unix());
		pathToVault1 = tmpFs.getPath("/vaultDir1");
		pathToVault2 = tmpFs.getPath("/vaultDir2");
		Files.createDirectory(pathToVault1);
		Files.createDirectory(pathToVault2);
		masterkeyFile1 = pathToVault1.resolve("masterkey.cryptomator");
		masterkeyFile2 = pathToVault2.resolve("masterkey.cryptomator");
	}

	@AfterAll
	public void teardown() throws IOException {
		tmpFs.close();
	}

	@Test
	@Order(1)
	@DisplayName("initialize vaults")
	public void initializeVaults() {
		Assertions.assertAll(
				() -> {
					CryptoFileSystemProvider.initialize(pathToVault1, "masterkey.cryptomator", "asd");
					Assertions.assertTrue(Files.isDirectory(pathToVault1.resolve("d")));
					Assertions.assertTrue(Files.isRegularFile(masterkeyFile1));
				}, () -> {
					byte[] pepper = "pepper".getBytes(StandardCharsets.US_ASCII);
					CryptoFileSystemProvider.initialize(pathToVault2, "masterkey.cryptomator", pepper, "asd");
					Assertions.assertTrue(Files.isDirectory(pathToVault2.resolve("d")));
					Assertions.assertTrue(Files.isRegularFile(masterkeyFile2));
				});
	}

	@Test
	@Order(2)
	@DisplayName("get filesystem with incorrect credentials")
	public void testGetFsWithWrongCredentials() {
		Assumptions.assumeTrue(Files.exists(masterkeyFile1));
		Assumptions.assumeTrue(Files.exists(masterkeyFile2));
		Assertions.assertAll(
				() -> {
					URI fsUri = CryptoFileSystemUri.create(pathToVault1);
					CryptoFileSystemProperties properties = cryptoFileSystemProperties() //
							.withFlags() //
							.withMasterkeyFilename("masterkey.cryptomator") //
							.withPassphrase("qwe") //
							.build();
					Assertions.assertThrows(InvalidPassphraseException.class, () -> {
						FileSystems.newFileSystem(fsUri, properties);
					});
				},
				() -> {
					byte[] pepper = "salt".getBytes(StandardCharsets.US_ASCII);
					URI fsUri = CryptoFileSystemUri.create(pathToVault2);
					CryptoFileSystemProperties properties = cryptoFileSystemProperties() //
							.withFlags() //
							.withMasterkeyFilename("masterkey.cryptomator") //
							.withPassphrase("qwe") //
							.withPepper(pepper)
							.build();
					Assertions.assertThrows(InvalidPassphraseException.class, () -> {
						FileSystems.newFileSystem(fsUri, properties);
					});
				});
	}

	@Test
	@Order(3)
	@DisplayName("change password")
	public void testChangePassword() {
		Assumptions.assumeTrue(Files.exists(masterkeyFile1));
		Assumptions.assumeTrue(Files.exists(masterkeyFile2));
		Assertions.assertAll(
				() -> {
					Path pathToVault = tmpFs.getPath("/tmpVault");
					Files.createDirectory(pathToVault);
					Path masterkeyFile = pathToVault.resolve("masterkey.cryptomator");
					Files.write(masterkeyFile, "{\"version\": 0}".getBytes(StandardCharsets.US_ASCII));
					Assertions.assertThrows(FileSystemNeedsMigrationException.class, () -> {
						CryptoFileSystemProvider.changePassphrase(pathToVault, "masterkey.cryptomator", "asd", "qwe");
					});
				},
				() -> {
					Assertions.assertThrows(InvalidPassphraseException.class, () -> {
						CryptoFileSystemProvider.changePassphrase(pathToVault1, "masterkey.cryptomator", "WRONG", "qwe");
					});
				},
				() -> {
					CryptoFileSystemProvider.changePassphrase(pathToVault1, "masterkey.cryptomator", "asd", "qwe");
				},
				() -> {
					byte[] pepper = "salt".getBytes(StandardCharsets.US_ASCII);
					Assertions.assertThrows(InvalidPassphraseException.class, () -> {
						CryptoFileSystemProvider.changePassphrase(pathToVault2, "masterkey.cryptomator", pepper, "asd", "qwe");
					});
				},
				() -> {
					byte[] pepper = "pepper".getBytes(StandardCharsets.US_ASCII);
					CryptoFileSystemProvider.changePassphrase(pathToVault2, "masterkey.cryptomator", pepper, "asd", "qwe");
				}
		);
	}

	@Test
	@Order(4)
	@DisplayName("get filesystem with correct credentials")
	public void testGetFsViaNioApi() {
		Assumptions.assumeTrue(Files.exists(masterkeyFile1));
		Assumptions.assumeTrue(Files.exists(masterkeyFile2));
		Assertions.assertAll(
				() -> {
					URI fsUri = CryptoFileSystemUri.create(pathToVault1);
					fs1 = FileSystems.newFileSystem(fsUri, cryptoFileSystemProperties().withPassphrase("qwe").build());
					Assertions.assertTrue(fs1 instanceof CryptoFileSystemImpl);

					FileSystem sameFs = FileSystems.getFileSystem(fsUri);
					Assertions.assertSame(fs1, sameFs);
				},
				() -> {
					byte[] pepper = "pepper".getBytes(StandardCharsets.US_ASCII);
					URI fsUri = CryptoFileSystemUri.create(pathToVault2);
					fs2 = FileSystems.newFileSystem(fsUri, cryptoFileSystemProperties().withPassphrase("qwe").withPepper(pepper).build());
					Assertions.assertTrue(fs2 instanceof CryptoFileSystemImpl);

					FileSystem sameFs = FileSystems.getFileSystem(fsUri);
					Assertions.assertSame(fs2, sameFs);
				});
	}

	@Test
	@Order(5)
	@DisplayName("touch /foo")
	public void testOpenAndCloseFileChannel() throws IOException {
		Assumptions.assumeTrue(fs1.isOpen());

		try (FileChannel ch = FileChannel.open(fs1.getPath("/foo"), EnumSet.of(StandardOpenOption.WRITE, StandardOpenOption.CREATE_NEW))) {
			Assertions.assertTrue(ch instanceof CleartextFileChannel);
		}
	}

	@Test
	@Order(6)
	@DisplayName("ln -s foo /link")
	public void testCreateSymlink() throws IOException {
		Path target = fs1.getPath("/foo");
		Assumptions.assumeTrue(Files.isRegularFile(target));
		Path link = fs1.getPath("/link");
		Files.createSymbolicLink(link, target);
	}

	@Test
	@Order(6)
	@DisplayName("echo 'hello world' > /link")
	public void testWriteToSymlink() throws IOException {
		Path link = fs1.getPath("/link");
		Assumptions.assumeTrue(Files.isSymbolicLink(link));

		try (WritableByteChannel ch = Files.newByteChannel(link, StandardOpenOption.WRITE)) {
			ch.write(StandardCharsets.US_ASCII.encode("hello world"));
		}
	}

	@Test
	@Order(7)
	@DisplayName("cat `readlink -f /link`")
	public void testReadFromSymlink() throws IOException {
		Path link = fs1.getPath("/link");
		Assumptions.assumeTrue(Files.isSymbolicLink(link));
		Path target = Files.readSymbolicLink(link);

		try (ReadableByteChannel ch = Files.newByteChannel(target, StandardOpenOption.READ)) {
			ByteBuffer buf = ByteBuffer.allocate(100);
			ch.read(buf);
			buf.flip();
			String str = StandardCharsets.US_ASCII.decode(buf).toString();
			Assertions.assertEquals("hello world", str);
		}
	}

	@Test
	@Order(8)
	@DisplayName("mkdir '/Internet Telefon Energie Wasser Webseitengeraffel Bus Bahn Mietwagen'")
	public void testLongFileNames() throws IOException {
		Path longNamePath = fs1.getPath("/Internet Telefon Energie Wasser Webseitengeraffel Bus Bahn Mietwagen");
		Files.createDirectory(longNamePath);
		Assertions.assertTrue(Files.isDirectory(longNamePath));
		MatcherAssert.assertThat(MoreFiles.listFiles(fs1.getPath("/")), Matchers.hasItem(longNamePath));
	}

	@Test
	@Order(9)
	@DisplayName("cp fs1:/foo fs2:/bar")
	public void testCopyFileAcrossFilesystem() throws IOException {
		Path file1 = fs1.getPath("/foo");
		Path file2 = fs2.getPath("/bar");
		Assumptions.assumeTrue(Files.isRegularFile(file1));
		Assumptions.assumeTrue(Files.notExists(file2));

		Files.copy(file1, file2);

		Assertions.assertArrayEquals(readAllBytes(file1), readAllBytes(file2));
	}

	@Test
	@Order(10)
	@DisplayName("echo 'goodbye world' > /foo")
	public void testWriteToFile() throws IOException {
		Path file1 = fs1.getPath("/foo");
		Assumptions.assumeTrue(Files.isRegularFile(file1));
		Files.write(file1, "goodbye world".getBytes());
	}

	@Test
	@Order(11)
	@DisplayName("cp -f fs1:/foo fs2:/bar")
	public void testCopyFileAcrossFilesystemReplaceExisting() throws IOException {
		Path file1 = fs1.getPath("/foo");
		Path file2 = fs2.getPath("/bar");
		Assumptions.assumeTrue(Files.isRegularFile(file1));
		Assumptions.assumeTrue(Files.isRegularFile(file2));

		Files.copy(file1, file2, REPLACE_EXISTING);

		Assertions.assertArrayEquals(readAllBytes(file1), readAllBytes(file2));
	}

	@Test
	@Order(12)
	@DisplayName("readattr /attributes.txt")
	public void testLazinessOfFileAttributeViews() throws IOException {
		Path file = fs1.getPath("/attributes.txt");
		Assumptions.assumeTrue(Files.notExists(file));

		BasicFileAttributeView attrView = Files.getFileAttributeView(file, BasicFileAttributeView.class);
		Assertions.assertNotNull(attrView);
		Assertions.assertThrows(NoSuchFileException.class, () -> {
			attrView.readAttributes();
		});

		Files.write(file, new byte[3], StandardOpenOption.CREATE_NEW);
		BasicFileAttributes attrs = attrView.readAttributes();
		Assertions.assertNotNull(attrs);
		Assertions.assertEquals(3, attrs.size());

		Files.delete(file);
		Assertions.assertThrows(NoSuchFileException.class, () -> {
			attrView.readAttributes();
		});
		Assertions.assertEquals(3, attrs.size()); // attrs should be immutable once they are read.
	}

	@Test
	@Order(13)
	@DisplayName("ln -s /linked/targetY /links/linkX")
	public void testSymbolicLinks() throws IOException {
		Path linksDir = fs1.getPath("/links");
		Assumptions.assumeTrue(Files.notExists(linksDir));
		Files.createDirectories(linksDir);

		Assertions.assertAll(
				() -> {
					Path link = linksDir.resolve("link1");
					Files.createDirectories(link.getParent());
					Files.createSymbolicLink(link, fs1.getPath("/linked/target1"));
					Path target = Files.readSymbolicLink(link);
					MatcherAssert.assertThat(target.getFileSystem(), is(link.getFileSystem())); // as per contract of readSymbolicLink
					MatcherAssert.assertThat(target.toString(), Matchers.equalTo("/linked/target1"));
					MatcherAssert.assertThat(link.resolveSibling(target).toString(), Matchers.equalTo("/linked/target1"));
				},
				() -> {
					Path link = linksDir.resolve("link2");
					Files.createDirectories(link.getParent());
					Files.createSymbolicLink(link, fs1.getPath("./target2"));
					Path target = Files.readSymbolicLink(link);
					MatcherAssert.assertThat(target.getFileSystem(), is(link.getFileSystem()));
					MatcherAssert.assertThat(target.toString(), Matchers.equalTo("./target2"));
					MatcherAssert.assertThat(link.resolveSibling(target).normalize().toString(), Matchers.equalTo("/links/target2"));
				},
				() -> {
					Path link = linksDir.resolve("link3");
					Files.createDirectories(link.getParent());
					Files.createSymbolicLink(link, fs1.getPath("../target3"));
					Path target = Files.readSymbolicLink(link);
					MatcherAssert.assertThat(target.getFileSystem(), is(link.getFileSystem()));
					MatcherAssert.assertThat(target.toString(), Matchers.equalTo("../target3"));
					MatcherAssert.assertThat(link.resolveSibling(target).normalize().toString(), Matchers.equalTo("/target3"));
				}
		);
	}

	@Test
	@Order(13)
	@DisplayName("mv -f fs1:/foo fs2:/baz")
	public void testMoveFileFromOneCryptoFileSystemToAnother() throws IOException {
		Path file1 = fs1.getPath("/foo");
		Path file2 = fs2.getPath("/baz");
		Assumptions.assumeTrue(Files.isRegularFile(file1));
		Assumptions.assumeTrue(Files.notExists(file2));
		byte[] contents = readAllBytes(file1);

		Files.move(file1, file2);

		Assertions.assertTrue(Files.notExists(file1));
		Assertions.assertTrue(Files.isRegularFile(file2));
		Assertions.assertArrayEquals(contents, readAllBytes(file2));
	}

	@Test
	@Order(14)
	@DisplayName("read and write dos attributes")
	public void testDosFileAttributes() throws IOException {
		Path file = fs1.getPath("/msDosAttributes.txt");
		Assumptions.assumeTrue(Files.notExists(file));
		Assumptions.assumeTrue(System.getProperty("os.name") != null && System.getProperty("os.name").startsWith("Windows"));

		Files.write(file, new byte[1]);

		Files.setAttribute(file, "dos:hidden", true);
		Files.setAttribute(file, "dos:system", true);
		Files.setAttribute(file, "dos:archive", true);
		Files.setAttribute(file, "dos:readOnly", true);

		MatcherAssert.assertThat(Files.getAttribute(file, "dos:hidden"), is(false));
		MatcherAssert.assertThat(Files.getAttribute(file, "dos:system"), is(false));
		MatcherAssert.assertThat(Files.getAttribute(file, "dos:archive"), is(false));
		MatcherAssert.assertThat(Files.getAttribute(file, "dos:readOnly"), is(true));

		Files.setAttribute(file, "dos:hidden", false);
		Files.setAttribute(file, "dos:system", false);
		Files.setAttribute(file, "dos:archive", false);
		Files.setAttribute(file, "dos:readOnly", false);

		MatcherAssert.assertThat(Files.getAttribute(file, "dos:hidden"), is(false));
		MatcherAssert.assertThat(Files.getAttribute(file, "dos:system"), is(false));
		MatcherAssert.assertThat(Files.getAttribute(file, "dos:archive"), is(false));
		MatcherAssert.assertThat(Files.getAttribute(file, "dos:readOnly"), is(false));
	}

}
