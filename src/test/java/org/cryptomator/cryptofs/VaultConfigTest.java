package org.cryptomator.cryptofs;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.Verification;
import org.cryptomator.cryptofs.common.Constants;
import org.cryptomator.cryptolib.api.CryptorProvider;
import org.cryptomator.cryptolib.api.Masterkey;
import org.cryptomator.cryptolib.api.MasterkeyLoader;
import org.cryptomator.cryptolib.api.MasterkeyLoadingFailedException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mockito;

import java.util.Arrays;

public class VaultConfigTest {

	private MasterkeyLoader masterkeyLoader = Mockito.mock(MasterkeyLoader.class);
	private byte[] rawKey = new byte[64];
	private Masterkey key = Mockito.mock(Masterkey.class);

	@BeforeEach
	public void setup() throws MasterkeyLoadingFailedException {
		Arrays.fill(rawKey, (byte) 0x55);
		Mockito.when(masterkeyLoader.loadKey(Mockito.any())).thenReturn(key);
		Mockito.when(key.getEncoded()).thenReturn(rawKey);
	}

	@Test
	@DisplayName("test VaultConfig.load() with invalid token")
	public void testLoadMalformedToken() {
		Assertions.assertThrows(VaultConfigLoadException.class, () -> {
			VaultConfig.load("hello world", masterkeyLoader, 42);
		});
	}

	@Nested
	@DisplayName("VaultConfig ...")
	public class WithExistingConfig {

		private VaultConfig originalConfig;

		@BeforeEach
		public void setup() throws MasterkeyLoadingFailedException {
			originalConfig = VaultConfig.createNew().cipherCombo(CryptorProvider.Scheme.SIV_CTRMAC).shorteningThreshold(220).build();
		}

		@Test
		@DisplayName("toToken() is HS256-signed")
		public void testToToken() {
			var token = originalConfig.toToken("TEST_KEY", rawKey);

			Assertions.assertNotNull(token);
			var decoded = JWT.decode(token);
			Assertions.assertEquals("HS256", decoded.getAlgorithm());
		}

	}

	@Nested
	@DisplayName("Using valid tokens...")
	public class WithValidToken {

		private static final String TOKEN_NONE = "eyJraWQiOiJURVNUX0tFWSIsInR5cCI6IkpXVCIsImFsZyI6Im5vbmUifQ.eyJmb3JtYXQiOjgsInNob3J0ZW5pbmdUaHJlc2hvbGQiOjIyMCwianRpIjoiZjRiMjlmM2EtNDdkNi00NjlmLTk2NGMtZjRjMmRhZWU4ZWI2IiwiY2lwaGVyQ29tYm8iOiJTSVZfQ1RSTUFDIn0.";
		private static final String TOKEN_HS256 = "eyJraWQiOiJURVNUX0tFWSIsInR5cCI6IkpXVCIsImFsZyI6IkhTMjU2In0.eyJmb3JtYXQiOjgsInNob3J0ZW5pbmdUaHJlc2hvbGQiOjIyMCwianRpIjoiZjRiMjlmM2EtNDdkNi00NjlmLTk2NGMtZjRjMmRhZWU4ZWI2IiwiY2lwaGVyQ29tYm8iOiJTSVZfQ1RSTUFDIn0.V7pqSXX1tBRgmntL1sXovnhNR4Z1_7z3Jzrq7NMqPO8";
		private static final String TOKEN_HS384 = "eyJraWQiOiJURVNUX0tFWSIsInR5cCI6IkpXVCIsImFsZyI6IkhTMzg0In0.eyJmb3JtYXQiOjgsInNob3J0ZW5pbmdUaHJlc2hvbGQiOjIyMCwianRpIjoiZjRiMjlmM2EtNDdkNi00NjlmLTk2NGMtZjRjMmRhZWU4ZWI2IiwiY2lwaGVyQ29tYm8iOiJTSVZfQ1RSTUFDIn0.rx03sCVAyrCmT6halPaFU46lu-DOd03iwDgvdw362hfgJj782q6xPXjAxdKeVKxG";
		private static final String TOKEN_HS512 = "eyJraWQiOiJURVNUX0tFWSIsInR5cCI6IkpXVCIsImFsZyI6IkhTNTEyIn0.eyJmb3JtYXQiOjgsInNob3J0ZW5pbmdUaHJlc2hvbGQiOjIyMCwianRpIjoiZjRiMjlmM2EtNDdkNi00NjlmLTk2NGMtZjRjMmRhZWU4ZWI2IiwiY2lwaGVyQ29tYm8iOiJTSVZfQ1RSTUFDIn0.fzkVI34Ou3z7RaFarS9VPCaA0NX9z7My14gAISTXJGKGNSID7xEcoaY56SBdWbU7Ta17KhxcHhbXffxk3Mzing";

		@Test
		public void testUnsupportedSignature() {
			VaultConfigLoadException thrown = Assertions.assertThrows(VaultConfigLoadException.class, () -> {
				VaultConfig.load(TOKEN_NONE, masterkeyLoader, 8);
			});
			Assertions.assertEquals("Unsupported signature algorithm: none", thrown.getMessage());
		}

		@DisplayName("load token")
		@ParameterizedTest(name = "signed with {0}")
		@CsvSource({"HS256," + TOKEN_HS256, "HS384," + TOKEN_HS384, "HS512," + TOKEN_HS512})
		public void testSuccessfulLoad(String algo, String token) throws VaultConfigLoadException, MasterkeyLoadingFailedException {
			Assumptions.assumeTrue(JWT.decode(token).getAlgorithm().equals(algo));

			var loaded = VaultConfig.load(token, masterkeyLoader, 8);

			Assertions.assertEquals(8, loaded.getVaultVersion());
			Assertions.assertEquals(CryptorProvider.Scheme.SIV_CTRMAC, loaded.getCipherCombo());
			Assertions.assertEquals(220, loaded.getShorteningThreshold());
		}

		@DisplayName("load using key with...")
		@ParameterizedTest(name = "invalid byte at position {0}")
		@ValueSource(ints = {0, 1, 2, 3, 10, 20, 30, 63})
		public void testLoadWithInvalidKey(int pos) {
			rawKey[pos] = (byte) 0x77;

			Assertions.assertThrows(VaultKeyInvalidException.class, () -> {
				VaultConfig.load(TOKEN_HS256, masterkeyLoader, 8);
			});
		}

	}

	@Test
	@DisplayName("test VaultConfig.createNew()...")
	public void testCreateNew() {
		var config = VaultConfig.createNew().cipherCombo(CryptorProvider.Scheme.SIV_CTRMAC).shorteningThreshold(220).build();

		Assertions.assertNotNull(config.getId());
		Assertions.assertEquals(Constants.VAULT_VERSION, config.getVaultVersion());
		Assertions.assertEquals(CryptorProvider.Scheme.SIV_CTRMAC, config.getCipherCombo());
		Assertions.assertEquals(220, config.getShorteningThreshold());
	}

	@Test
	@DisplayName("test VaultConfig.load(...)")
	public void testLoadExisting() throws VaultConfigLoadException, MasterkeyLoadingFailedException {
		var decodedJwt = Mockito.mock(DecodedJWT.class);
		var formatClaim = Mockito.mock(Claim.class);
		var cipherComboClaim = Mockito.mock(Claim.class);
		var maxFilenameLenClaim = Mockito.mock(Claim.class);
		var key = Mockito.mock(Masterkey.class);
		var verification = Mockito.mock(Verification.class);
		var verifier = Mockito.mock(JWTVerifier.class);
		Mockito.when(decodedJwt.getKeyId()).thenReturn("test:key");
		Mockito.when(decodedJwt.getAlgorithm()).thenReturn("HS256");
		Mockito.when(decodedJwt.getClaim("format")).thenReturn(formatClaim);
		Mockito.when(decodedJwt.getClaim("cipherCombo")).thenReturn(cipherComboClaim);
		Mockito.when(decodedJwt.getClaim("shorteningThreshold")).thenReturn(maxFilenameLenClaim);
		Mockito.when(key.getEncoded()).thenReturn(new byte[64]);
		Mockito.when(verification.withClaim("format", 42)).thenReturn(verification);
		Mockito.when(verification.build()).thenReturn(verifier);
		Mockito.when(verifier.verify(decodedJwt)).thenReturn(decodedJwt);
		Mockito.when(formatClaim.asInt()).thenReturn(42);
		Mockito.when(cipherComboClaim.asString()).thenReturn("SIV_CTRMAC");
		Mockito.when(maxFilenameLenClaim.asInt()).thenReturn(220);
		try (var jwtMock = Mockito.mockStatic(JWT.class)) {
			jwtMock.when(() -> JWT.decode("jwt-vault-config")).thenReturn(decodedJwt);
			jwtMock.when(() -> JWT.require(Mockito.any())).thenReturn(verification);

			var config = VaultConfig.load("jwt-vault-config", masterkeyLoader, 42);
			Assertions.assertNotNull(config);
			Assertions.assertEquals(42, config.getVaultVersion());
		}
	}

}