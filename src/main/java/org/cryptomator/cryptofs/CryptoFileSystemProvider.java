/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptofs;

import org.cryptomator.cryptofs.ch.AsyncDelegatingFileChannel;
import org.cryptomator.cryptofs.common.Constants;
import org.cryptomator.cryptofs.common.FileSystemCapabilityChecker;
import org.cryptomator.cryptofs.common.MasterkeyBackupFileHasher;
import org.cryptomator.cryptofs.migration.Migrators;
import org.cryptomator.cryptofs.migration.api.MigrationContinuationListener;
import org.cryptomator.cryptolib.Cryptors;
import org.cryptomator.cryptolib.api.Cryptor;
import org.cryptomator.cryptolib.api.CryptorProvider;
import org.cryptomator.cryptolib.api.InvalidPassphraseException;

import java.io.IOException;
import java.net.URI;
import java.nio.channels.AsynchronousFileChannel;
import java.nio.channels.FileChannel;
import java.nio.channels.SeekableByteChannel;
import java.nio.file.AccessMode;
import java.nio.file.CopyOption;
import java.nio.file.DirectoryStream;
import java.nio.file.DirectoryStream.Filter;
import java.nio.file.FileStore;
import java.nio.file.FileSystem;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.NoSuchFileException;
import java.nio.file.NotDirectoryException;
import java.nio.file.OpenOption;
import java.nio.file.Path;
import java.nio.file.ProviderMismatchException;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.FileAttribute;
import java.nio.file.attribute.FileAttributeView;
import java.nio.file.spi.FileSystemProvider;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.text.Normalizer;
import java.text.Normalizer.Form;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ExecutorService;

import static java.nio.file.StandardCopyOption.ATOMIC_MOVE;
import static java.nio.file.StandardCopyOption.REPLACE_EXISTING;
import static java.nio.file.StandardOpenOption.CREATE_NEW;
import static java.nio.file.StandardOpenOption.WRITE;

/**
 * <p>
 * A {@link FileSystemProvider} for {@link CryptoFileSystem CryptoFileSystems}.
 * <p>
 * All {@code FileSystem} instances created by {@link CryptoFileSystemProvider} are instances of {@code CryptoFileSystem}.
 *
 * <b>Usage</b>
 * <p>
 * It is recommended to use {@link CryptoFileSystemProvider#newFileSystem(Path, CryptoFileSystemProperties)} to create a CryptoFileSystem. To do this:
 *
 * <blockquote>
 *
 * <pre>
 * Path storageLocation = Paths.get("/home/cryptobot/vault");
 * FileSystem fileSystem = CryptoFileSystemProvider.newFileSystem(
 * 	storageLocation,
 *    {@link CryptoFileSystemProperties cryptoFileSystemProperties()}
 * 		.withPassword("password")
 * 		.withFlags(FileSystemFlags.READONLY)
 * 		.build());
 * </pre>
 *
 * </blockquote>
 * <p>
 * Afterwards you can use the created {@code FileSystem} to create paths, do directory listings, create files and so on.
 * <p>
 * <p>
 * To create a new FileSystem from a URI using {@link FileSystems#newFileSystem(URI, Map)} you may have a look at {@link CryptoFileSystemUri}.
 *
 * @see CryptoFileSystemUri
 * @see CryptoFileSystemProperties
 * @see FileSystems
 * @see FileSystem
 */
public class CryptoFileSystemProvider extends FileSystemProvider {

	private static final CryptorProvider CRYPTOR_PROVIDER = Cryptors.version1(strongSecureRandom());

	private final CryptoFileSystems fileSystems;
	private final MoveOperation moveOperation;
	private final CopyOperation copyOperation;

	public CryptoFileSystemProvider() {
		this(DaggerCryptoFileSystemProviderComponent.builder().cryptorProvider(CRYPTOR_PROVIDER).build());
	}

	/**
	 * visible for testing
	 */
	CryptoFileSystemProvider(CryptoFileSystemProviderComponent component) {
		this.fileSystems = component.fileSystems();
		this.moveOperation = component.moveOperation();
		this.copyOperation = component.copyOperation();
	}

	private static SecureRandom strongSecureRandom() {
		try {
			return SecureRandom.getInstanceStrong();
		} catch (NoSuchAlgorithmException e) {
			throw new IllegalStateException("A strong algorithm must exist in every Java platform.", e);
		}
	}

	/**
	 * Typesafe alternative to {@link FileSystems#newFileSystem(URI, Map)}. Default way to retrieve a CryptoFS instance.
	 *
	 * @param pathToVault Path to this vault's storage location
	 * @param properties Parameters used during initialization of the file system
	 * @return a new file system
	 * @throws FileSystemNeedsMigrationException if the vault format needs to get updated and <code>properties</code> did not contain a flag for implicit migration.
	 * @throws FileSystemCapabilityChecker.MissingCapabilityException If the underlying filesystem lacks features required to store a vault
	 * @throws IOException if an I/O error occurs creating the file system
	 */
	public static CryptoFileSystem newFileSystem(Path pathToVault, CryptoFileSystemProperties properties) throws FileSystemNeedsMigrationException, IOException {
		URI uri = CryptoFileSystemUri.create(pathToVault.toAbsolutePath());
		return (CryptoFileSystem) FileSystems.newFileSystem(uri, properties);
	}

	/**
	 * Creates a new vault at the given directory path.
	 *
	 * @param pathToVault Path to a not yet existing directory
	 * @param masterkeyFilename Name of the masterkey file
	 * @param passphrase Passphrase that should be used to unlock the vault
	 * @throws NotDirectoryException If the given path is not an existing directory.
	 * @throws FileSystemCapabilityChecker.MissingCapabilityException If the underlying filesystem lacks features required to store a vault
	 * @throws IOException If the vault structure could not be initialized due to I/O errors
	 * @since 1.3.0
	 */
	public static void initialize(Path pathToVault, String masterkeyFilename, CharSequence passphrase) throws NotDirectoryException, IOException {
		initialize(pathToVault, masterkeyFilename, new byte[0], passphrase);
	}

	/**
	 * Creates a new vault at the given directory path.
	 *
	 * @param pathToVault Path to a not yet existing directory
	 * @param masterkeyFilename Name of the masterkey file
	 * @param pepper Application-specific pepper used during key derivation
	 * @param passphrase Passphrase that should be used to unlock the vault
	 * @throws NotDirectoryException If the given path is not an existing directory.
	 * @throws FileSystemCapabilityChecker.MissingCapabilityException If the underlying filesystem lacks features required to store a vault
	 * @throws IOException If the vault structure could not be initialized due to I/O errors
	 * @since 1.3.2
	 */
	public static void initialize(Path pathToVault, String masterkeyFilename, byte[] pepper, CharSequence passphrase) throws NotDirectoryException, IOException {
		if (!Files.isDirectory(pathToVault)) {
			throw new NotDirectoryException(pathToVault.toString());
		}
		try (Cryptor cryptor = CRYPTOR_PROVIDER.createNew()) {
			// save masterkey file:
			Path masterKeyPath = pathToVault.resolve(masterkeyFilename);
			byte[] keyFileContents = cryptor.writeKeysToMasterkeyFile(Normalizer.normalize(passphrase, Form.NFC), pepper, Constants.VAULT_VERSION).serialize();
			Files.write(masterKeyPath, keyFileContents, CREATE_NEW, WRITE);
			// create "d/RO/OTDIRECTORY":
			String rootDirHash = cryptor.fileNameCryptor().hashDirectoryId(Constants.ROOT_DIR_ID);
			Path rootDirPath = pathToVault.resolve(Constants.DATA_DIR_NAME).resolve(rootDirHash.substring(0, 2)).resolve(rootDirHash.substring(2));
			Files.createDirectories(rootDirPath);
		}
		assert containsVault(pathToVault, masterkeyFilename);
	}

	/**
	 * Checks if the folder represented by the given path exists and contains a valid vault structure.
	 *
	 * @param pathToVault A directory path
	 * @param masterkeyFilename Name of the masterkey file
	 * @return <code>true</code> if the directory seems to contain a vault.
	 * @since 1.1.0
	 */
	public static boolean containsVault(Path pathToVault, String masterkeyFilename) {
		Path masterKeyPath = pathToVault.resolve(masterkeyFilename);
		Path dataDirPath = pathToVault.resolve(Constants.DATA_DIR_NAME);
		return Files.isReadable(masterKeyPath) && Files.isDirectory(dataDirPath);
	}

	/**
	 * Changes the passphrase of a vault at the given path.
	 *
	 * @param pathToVault Vault directory
	 * @param masterkeyFilename Name of the masterkey file
	 * @param oldPassphrase Current passphrase
	 * @param newPassphrase Future passphrase
	 * @throws InvalidPassphraseException If <code>oldPassphrase</code> can not be used to unlock the vault.
	 * @throws FileSystemNeedsMigrationException if the vault format needs to get updated.
	 * @throws IOException If the masterkey could not be read or written.
	 * @see #changePassphrase(Path, String, byte[], CharSequence, CharSequence)
	 * @since 1.1.0
	 */
	public static void changePassphrase(Path pathToVault, String masterkeyFilename, CharSequence oldPassphrase, CharSequence newPassphrase)
			throws InvalidPassphraseException, FileSystemNeedsMigrationException, IOException {
		changePassphrase(pathToVault, masterkeyFilename, new byte[0], oldPassphrase, newPassphrase);
	}

	/**
	 * Changes the passphrase of a vault at the given path.
	 *
	 * @param pathToVault Vault directory
	 * @param masterkeyFilename Name of the masterkey file
	 * @param pepper An application-specific pepper added to the salt during key-derivation (if applicable)
	 * @param oldPassphrase Current passphrase
	 * @param newPassphrase Future passphrase
	 * @throws InvalidPassphraseException If <code>oldPassphrase</code> can not be used to unlock the vault.
	 * @throws FileSystemNeedsMigrationException if the vault format needs to get updated.
	 * @throws IOException If the masterkey could not be read or written.
	 * @since 1.4.0
	 */
	public static void changePassphrase(Path pathToVault, String masterkeyFilename, byte[] pepper, CharSequence oldPassphrase, CharSequence newPassphrase)
			throws InvalidPassphraseException, FileSystemNeedsMigrationException, IOException {
		if (Migrators.get().needsMigration(pathToVault, masterkeyFilename)) {
			throw new FileSystemNeedsMigrationException(pathToVault);
		}
		String normalizedOldPassphrase = Normalizer.normalize(oldPassphrase, Form.NFC);
		String normalizedNewPassphrase = Normalizer.normalize(newPassphrase, Form.NFC);
		Path masterKeyPath = pathToVault.resolve(masterkeyFilename);
		byte[] oldMasterkeyBytes = Files.readAllBytes(masterKeyPath);
		byte[] newMasterkeyBytes = Cryptors.changePassphrase(CRYPTOR_PROVIDER, oldMasterkeyBytes, pepper, normalizedOldPassphrase, normalizedNewPassphrase);
		Path backupKeyPath = pathToVault.resolve(masterkeyFilename + MasterkeyBackupFileHasher.generateFileIdSuffix(oldMasterkeyBytes) + Constants.MASTERKEY_BACKUP_SUFFIX);
		Files.move(masterKeyPath, backupKeyPath, REPLACE_EXISTING, ATOMIC_MOVE);
		Files.write(masterKeyPath, newMasterkeyBytes, CREATE_NEW, WRITE);
	}

	/**
	 * Exports the raw key for backup purposes or external key management.
	 *
	 * @param pathToVault       Vault directory
	 * @param masterkeyFilename Name of the masterkey file
	 * @param pepper            An application-specific pepper added to the salt during key-derivation (if applicable)
	 * @param passphrase        Current passphrase
	 * @return A 64 byte array consisting of 32 byte aes key and 32 byte mac key
	 * @since 1.9.0
	 */
	public static byte[] exportRawKey(Path pathToVault, String masterkeyFilename, byte[] pepper, CharSequence passphrase) throws InvalidPassphraseException, IOException {
		String normalizedPassphrase = Normalizer.normalize(passphrase, Form.NFC);
		Path masterKeyPath = pathToVault.resolve(masterkeyFilename);
		byte[] masterKeyBytes = Files.readAllBytes(masterKeyPath);
		return Cryptors.exportRawKey(CRYPTOR_PROVIDER, masterKeyBytes, pepper, normalizedPassphrase);
	}

	/**
	 * Imports a raw key from backup or external key management.
	 *
	 * @param pathToVault       Vault directory
	 * @param masterkeyFilename Name of the masterkey file
	 * @param pepper            An application-specific pepper added to the salt during key-derivation (if applicable)
	 * @param passphrase        Future passphrase
	 * @since 1.9.0
	 */
	public static void restoreRawKey(Path pathToVault, String masterkeyFilename, byte[] rawKey, byte[] pepper, CharSequence passphrase) throws InvalidPassphraseException, IOException {
		String normalizedPassphrase = Normalizer.normalize(passphrase, Form.NFC);
		byte[] masterKeyBytes = Cryptors.restoreRawKey(CRYPTOR_PROVIDER, rawKey, pepper, normalizedPassphrase, Constants.VAULT_VERSION);
		Path masterKeyPath = pathToVault.resolve(masterkeyFilename);
		if (Files.exists(masterKeyPath)) {
			byte[] oldMasterkeyBytes = Files.readAllBytes(masterKeyPath);
			Path backupKeyPath = pathToVault.resolve(masterkeyFilename + MasterkeyBackupFileHasher.generateFileIdSuffix(oldMasterkeyBytes) + Constants.MASTERKEY_BACKUP_SUFFIX);
			Files.move(masterKeyPath, backupKeyPath, REPLACE_EXISTING, ATOMIC_MOVE);
		}
		Files.write(masterKeyPath, masterKeyBytes, CREATE_NEW, WRITE);
	}

	/**
	 * @deprecated only for testing
	 */
	@Deprecated
	CryptoFileSystems getCryptoFileSystems() {
		return fileSystems;
	}

	@Override
	public String getScheme() {
		return CryptoFileSystemUri.URI_SCHEME;
	}

	@Override
	public CryptoFileSystem newFileSystem(URI uri, Map<String, ?> rawProperties) throws IOException {
		CryptoFileSystemUri parsedUri = CryptoFileSystemUri.parse(uri);
		CryptoFileSystemProperties properties = CryptoFileSystemProperties.wrap(rawProperties);

		// TODO remove implicit initialization in 2.0.0
		initializeFileSystemIfRequired(parsedUri, properties);
		migrateFileSystemIfRequired(parsedUri, properties);

		return fileSystems.create(this, parsedUri.pathToVault(), properties);
	}

	@Deprecated
	private void migrateFileSystemIfRequired(CryptoFileSystemUri parsedUri, CryptoFileSystemProperties properties) throws IOException, FileSystemNeedsMigrationException {
		if (Migrators.get().needsMigration(parsedUri.pathToVault(), properties.masterkeyFilename())) {
			if (properties.migrateImplicitly()) {
				Migrators.get().migrate(parsedUri.pathToVault(), properties.masterkeyFilename(), properties.passphrase(), (state, progress) -> {}, event -> MigrationContinuationListener.ContinuationResult.PROCEED);
			} else {
				throw new FileSystemNeedsMigrationException(parsedUri.pathToVault());
			}
		}
	}

	@Deprecated
	private void initializeFileSystemIfRequired(CryptoFileSystemUri parsedUri, CryptoFileSystemProperties properties) throws NotDirectoryException, IOException, NoSuchFileException {
		if (!CryptoFileSystemProvider.containsVault(parsedUri.pathToVault(), properties.masterkeyFilename())) {
			if (properties.initializeImplicitly()) {
				CryptoFileSystemProvider.initialize(parsedUri.pathToVault(), properties.masterkeyFilename(), properties.passphrase());
			} else {
				throw new NoSuchFileException(parsedUri.pathToVault().toString(), null, "Vault not initialized.");
			}
		}
	}

	@Override
	public CryptoFileSystem getFileSystem(URI uri) {
		CryptoFileSystemUri parsedUri = CryptoFileSystemUri.parse(uri);
		return fileSystems.get(parsedUri.pathToVault());
	}

	@Override
	public Path getPath(URI uri) {
		CryptoFileSystemUri parsedUri = CryptoFileSystemUri.parse(uri);
		return fileSystems.get(parsedUri.pathToVault()).getPath(parsedUri.pathInsideVault());
	}

	@Override
	public AsynchronousFileChannel newAsynchronousFileChannel(Path cleartextPath, Set<? extends OpenOption> options, ExecutorService executor, FileAttribute<?>... attrs) throws IOException {
		if (options.contains(StandardOpenOption.APPEND)) {
			throw new IllegalArgumentException("AsynchronousFileChannel can not be opened in append mode");
		}
		return new AsyncDelegatingFileChannel(newFileChannel(cleartextPath, options, attrs), executor);
	}

	@Override
	public FileChannel newFileChannel(Path cleartextPath, Set<? extends OpenOption> optionsSet, FileAttribute<?>... attrs) throws IOException {
		return fileSystem(cleartextPath).newFileChannel(CryptoPath.castAndAssertAbsolute(cleartextPath), optionsSet, attrs);
	}

	@Override
	public SeekableByteChannel newByteChannel(Path cleartextPath, Set<? extends OpenOption> options, FileAttribute<?>... attrs) throws IOException {
		return newFileChannel(cleartextPath, options, attrs);
	}

	@Override
	public DirectoryStream<Path> newDirectoryStream(Path cleartextDir, Filter<? super Path> filter) throws IOException {
		return fileSystem(cleartextDir).newDirectoryStream(CryptoPath.castAndAssertAbsolute(cleartextDir), filter);
	}

	@Override
	public void createDirectory(Path cleartextDir, FileAttribute<?>... attrs) throws IOException {
		fileSystem(cleartextDir).createDirectory(CryptoPath.castAndAssertAbsolute(cleartextDir), attrs);
	}

	@Override
	public void delete(Path cleartextPath) throws IOException {
		fileSystem(cleartextPath).delete(CryptoPath.castAndAssertAbsolute(cleartextPath));
	}

	@Override
	public void copy(Path cleartextSource, Path cleartextTarget, CopyOption... options) throws IOException {
		assertSameProvider(cleartextSource);
		assertSameProvider(cleartextTarget);
		copyOperation.copy(CryptoPath.castAndAssertAbsolute(cleartextSource), CryptoPath.castAndAssertAbsolute(cleartextTarget), options);
	}

	@Override
	public void move(Path cleartextSource, Path cleartextTarget, CopyOption... options) throws IOException {
		assertSameProvider(cleartextSource);
		assertSameProvider(cleartextTarget);
		moveOperation.move(CryptoPath.castAndAssertAbsolute(cleartextSource), CryptoPath.castAndAssertAbsolute(cleartextTarget), options);
	}

	@Override
	public boolean isSameFile(Path cleartextPath, Path cleartextPath2) throws IOException {
		return cleartextPath.getFileSystem() == cleartextPath2.getFileSystem() //
				&& cleartextPath.toRealPath().equals(cleartextPath2.toRealPath());
	}

	@Override
	public boolean isHidden(Path cleartextPath) throws IOException {
		return fileSystem(cleartextPath).isHidden(CryptoPath.castAndAssertAbsolute(cleartextPath));
	}

	@Override
	public FileStore getFileStore(Path cleartextPath) throws IOException {
		return fileSystem(cleartextPath).getFileStore();
	}

	@Override
	public void checkAccess(Path cleartextPath, AccessMode... modes) throws IOException {
		fileSystem(cleartextPath).checkAccess(CryptoPath.castAndAssertAbsolute(cleartextPath), modes);
	}

	@Override
	public void createSymbolicLink(Path cleartextPath, Path target, FileAttribute<?>... attrs) throws IOException {
		fileSystem(cleartextPath).createSymbolicLink(CryptoPath.castAndAssertAbsolute(cleartextPath), target, attrs);
	}

	@Override
	public Path readSymbolicLink(Path cleartextPath) throws IOException {
		return fileSystem(cleartextPath).readSymbolicLink(CryptoPath.castAndAssertAbsolute(cleartextPath));
	}

	@Override
	public <V extends FileAttributeView> V getFileAttributeView(Path cleartextPath, Class<V> type, LinkOption... options) {
		return fileSystem(cleartextPath).getFileAttributeView(CryptoPath.castAndAssertAbsolute(cleartextPath), type, options);
	}

	@Override
	public <A extends BasicFileAttributes> A readAttributes(Path cleartextPath, Class<A> type, LinkOption... options) throws IOException {
		return fileSystem(cleartextPath).readAttributes(CryptoPath.castAndAssertAbsolute(cleartextPath), type, options);
	}

	@Override
	public Map<String, Object> readAttributes(Path cleartextPath, String attributes, LinkOption... options) throws IOException {
		return fileSystem(cleartextPath).readAttributes(CryptoPath.castAndAssertAbsolute(cleartextPath), attributes, options);
	}

	@Override
	public void setAttribute(Path cleartextPath, String attribute, Object value, LinkOption... options) throws IOException {
		fileSystem(cleartextPath).setAttribute(CryptoPath.castAndAssertAbsolute(cleartextPath), attribute, value, options);
	}

	private CryptoFileSystemImpl fileSystem(Path path) {
		assertSameProvider(path);
		CryptoFileSystemImpl fs = CryptoPath.cast(path).getFileSystem();
		fs.assertOpen();
		return fs;
	}

	private void assertSameProvider(Path path) {
		if (path.getFileSystem().provider() != this) {
			throw new ProviderMismatchException("Used a path from provider " + path.getFileSystem().provider() + " with provider " + this);
		}
	}

}
