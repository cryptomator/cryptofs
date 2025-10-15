/**
 * Package containing all necessary components for the in-use feature.
 * <p>
 * A file is considered <em>in use</em>, if a valid in-use-file exists.
 * <p>
 * A valid in-use file has the same filename as the file, which should be marked in use.
 * Its file extension is {@value org.cryptomator.cryptofs.common.Constants#INUSE_FILE_SUFFIX}.
 * It contains Java Properties, encrypted with the vault masterkey:
 * <ul>
 *   <li><code>owner</code> — name of the filesystem owner</li>
 *   <li><code>lastUpdated</code> — UTC timestamp in ISO-8601</li>
 * </ul>
 * <p>
 * To check if a file is in-use or to mark it as in-use, see {@link org.cryptomator.cryptofs.inuse.InUseManager} and its implementation {@link org.cryptomator.cryptofs.inuse.RealInUseManager}
 */
package org.cryptomator.cryptofs.inuse;