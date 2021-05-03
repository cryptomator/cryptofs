package org.cryptomator.cryptofs;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.InvalidClaimException;
import com.auth0.jwt.exceptions.JWTDecodeException;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.exceptions.SignatureVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.cryptomator.cryptofs.common.Constants;
import org.cryptomator.cryptolib.api.Masterkey;
import org.cryptomator.cryptolib.api.MasterkeyLoader;
import org.cryptomator.cryptolib.api.MasterkeyLoadingFailedException;

import java.net.URI;
import java.util.Arrays;
import java.util.UUID;

/**
 * Typesafe representation of vault configuration files.
 * <p>
 * To prevent config tampering, such as downgrade attacks, vault configurations are cryptographically signed using HMAC-256
 * with the vault's 64 byte master key.
 * <p>
 * If the signature could be successfully verified, the configuration can be assumed valid and the masterkey can be assumed
 * eligible for the vault.
 * <p>
 * When {@link #load(String, MasterkeyLoader, int) loading} a vault configuration, a key must be provided and the signature is checked.
 * It is impossible to create an instance of this class from an existing configuration without signature verification.
 */
public class VaultConfig {

	private static final String JSON_KEY_VAULTVERSION = "format";
	private static final String JSON_KEY_CIPHERCONFIG = "cipherCombo";
	private static final String JSON_KEY_SHORTENING_THRESHOLD = "shorteningThreshold";

	private final String id;
	private final int vaultVersion;
	private final VaultCipherCombo cipherCombo;
	private final int shorteningThreshold;

	private VaultConfig(DecodedJWT verifiedConfig) {
		this.id = verifiedConfig.getId();
		this.vaultVersion = verifiedConfig.getClaim(JSON_KEY_VAULTVERSION).asInt();
		this.cipherCombo = VaultCipherCombo.valueOf(verifiedConfig.getClaim(JSON_KEY_CIPHERCONFIG).asString());
		this.shorteningThreshold = verifiedConfig.getClaim(JSON_KEY_SHORTENING_THRESHOLD).asInt();
	}

	private VaultConfig(VaultConfigBuilder builder) {
		this.id = builder.id;
		this.vaultVersion = builder.vaultVersion;
		this.cipherCombo = builder.cipherCombo;
		this.shorteningThreshold = builder.shorteningThreshold;
	}

	public String getId() {
		return id;
	}

	public int getVaultVersion() {
		return vaultVersion;
	}

	public VaultCipherCombo getCipherCombo() {
		return cipherCombo;
	}

	public int getShorteningThreshold() {
		return shorteningThreshold;
	}

	public String toToken(String keyId, byte[] rawKey) {
		return JWT.create() //
				.withKeyId(keyId) //
				.withJWTId(id) //
				.withClaim(JSON_KEY_VAULTVERSION, vaultVersion) //
				.withClaim(JSON_KEY_CIPHERCONFIG, cipherCombo.name()) //
				.withClaim(JSON_KEY_SHORTENING_THRESHOLD, shorteningThreshold) //
				.sign(Algorithm.HMAC256(rawKey));
	}

	/**
	 * Convenience wrapper for {@link #decode(String)} and {@link UnverifiedVaultConfig#verify(byte[], int)}
	 *
	 * @param token                The token
	 * @param keyLoader            A key loader capable of providing a key for this token
	 * @param expectedVaultVersion The vault version this token should contain
	 * @return The decoded configuration
	 * @throws MasterkeyLoadingFailedException If the key loader was unable to provide a key for this vault configuration
	 * @throws VaultConfigLoadException        When loading the configuration fails
	 */
	public static VaultConfig load(String token, MasterkeyLoader keyLoader, int expectedVaultVersion) throws MasterkeyLoadingFailedException, VaultConfigLoadException {
		var configLoader = decode(token);
		byte[] rawKey = new byte[0];
		try (Masterkey key = keyLoader.loadKey(configLoader.getKeyId())) {
			rawKey = key.getEncoded();
			return configLoader.verify(rawKey, expectedVaultVersion);
		} finally {
			Arrays.fill(rawKey, (byte) 0x00);
		}
	}

	/**
	 * Decodes a vault configuration stored in JWT format to load it
	 *
	 * @param token The token
	 * @return A loader object that allows loading the configuration (if providing the required key)
	 * @throws VaultConfigLoadException When parsing the token failed
	 */
	public static UnverifiedVaultConfig decode(String token) throws VaultConfigLoadException {
		try {
			return new UnverifiedVaultConfig(JWT.decode(token));
		} catch (JWTDecodeException e) {
			throw new VaultConfigLoadException("Failed to parse config: " + token);
		}
	}

	/**
	 * Create a new configuration object for a new vault.
	 *
	 * @return A new configuration builder
	 */
	public static VaultConfigBuilder createNew() {
		return new VaultConfigBuilder();
	}

	public static class UnverifiedVaultConfig {

		private final DecodedJWT unverifiedConfig;

		private UnverifiedVaultConfig(DecodedJWT unverifiedConfig) {
			this.unverifiedConfig = unverifiedConfig;
		}

		/**
		 * @return The ID of the key required to {@link #verify(byte[], int) load} this config
		 */
		public URI getKeyId() {
			return URI.create(unverifiedConfig.getKeyId());
		}

		/**
		 * @return The unverified vault version (signature not verified)
		 */
		public int allegedVaultVersion() {
			return unverifiedConfig.getClaim(JSON_KEY_VAULTVERSION).asInt();
		}

		/**
		 * @return The unverified shortening threshold (signature not verified)
		 */
		public int allegedShorteningThreshold() {
			return unverifiedConfig.getClaim(JSON_KEY_SHORTENING_THRESHOLD).asInt();
		}

		/**
		 * Decodes a vault configuration stored in JWT format.
		 *
		 * @param rawKey               The key matching the id in {@link #getKeyId()}
		 * @param expectedVaultVersion The vault version this token should contain
		 * @return The decoded configuration
		 * @throws VaultKeyInvalidException      If the provided key was invalid
		 * @throws VaultVersionMismatchException If the token did not match the expected vault version
		 * @throws VaultConfigLoadException      Generic parse error
		 */
		public VaultConfig verify(byte[] rawKey, int expectedVaultVersion) throws VaultKeyInvalidException, VaultVersionMismatchException, VaultConfigLoadException {
			try {
				var verifier = JWT.require(Algorithm.HMAC256(rawKey)) //
						.withClaim(JSON_KEY_VAULTVERSION, expectedVaultVersion) //
						.build();
				var verifiedConfig = verifier.verify(unverifiedConfig);
				return new VaultConfig(verifiedConfig);
			} catch (SignatureVerificationException e) {
				throw new VaultKeyInvalidException();
			} catch (InvalidClaimException e) {
				throw new VaultVersionMismatchException("Vault config not for version " + expectedVaultVersion);
			} catch (JWTVerificationException e) {
				throw new VaultConfigLoadException("Failed to verify vault config: " + unverifiedConfig.getToken());
			}
		}
	}

	public static class VaultConfigBuilder {

		private final String id = UUID.randomUUID().toString();
		private final int vaultVersion = Constants.VAULT_VERSION;
		private VaultCipherCombo cipherCombo;
		private int shorteningThreshold;

		public VaultConfigBuilder cipherCombo(VaultCipherCombo cipherCombo) {
			this.cipherCombo = cipherCombo;
			return this;
		}

		public VaultConfigBuilder shorteningThreshold(int shorteningThreshold) {
			this.shorteningThreshold = shorteningThreshold;
			return this;
		}

		public VaultConfig build() {
			return new VaultConfig(this);
		}

	}

}
