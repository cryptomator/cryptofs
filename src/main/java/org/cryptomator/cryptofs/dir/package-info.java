/**
 * This package contains classes used during directory listing.
 * <p>
 * When calling {@link java.nio.file.Files#newDirectoryStream(java.nio.file.Path) Files.newDirectoryStream(cleartextPath)},
 * {@link org.cryptomator.cryptofs.dir.DirectoryStreamFactory} will determine the corresponding <code>ciphertextPath</code>
 * and open a DirectoryStream on it.
 * <p>
 * Each node will then be passed through a pipes-and-filters system consisting of the vairous classes in this package, resulting in cleartext nodes.
 * <p>
 * As a side effect certain auto-repair steps are applied, if non-standard ciphertext files are encountered and deemed recoverable.
 */
package org.cryptomator.cryptofs.dir;