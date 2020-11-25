package org.cryptomator.cryptofs;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.Verification;
import org.cryptomator.cryptofs.common.Constants;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mockito;

import java.util.Arrays;

public class VaultConfigTest {

	@Test
	public void testLoadMalformedToken() {
		Assertions.assertThrows(VaultConfigLoadException.class, () -> {
			VaultConfig.load("hello world", ignored -> new byte[64], 42);
		});
	}

	@Nested
	public class WithValidToken {

		private byte[] key = new byte[64];
		private VaultConfig originalConfig;
		private String token;


		@BeforeEach
		public void setup() {
			Arrays.fill(key, (byte) 0x55);
			originalConfig = VaultConfig.createNew().cipherMode(VaultCipherMode.SIV_CTRMAC).maxFilenameLength(220).build();
			token = originalConfig.toToken("TEST_KEY", key);
		}

		@Test
		public void testSuccessfulLoad() throws VaultConfigLoadException, KeyLoadingFailedException {
			var loaded = VaultConfig.load(token, ignored -> key, originalConfig.getVaultVersion());

			Assertions.assertEquals(originalConfig.getId(), loaded.getId());
			Assertions.assertEquals(originalConfig.getVaultVersion(), loaded.getVaultVersion());
			Assertions.assertEquals(originalConfig.getCiphermode(), loaded.getCiphermode());
			Assertions.assertEquals(originalConfig.getMaxFilenameLength(), loaded.getMaxFilenameLength());
		}

		@ParameterizedTest
		@ValueSource(ints = {0, 1, 2, 3, 10, 20, 30, 63})
		public void testLoadWithInvalidKey(int pos) {
			key[pos] = (byte) 0x77;

			Assertions.assertThrows(VaultKeyInvalidException.class, () -> {
				VaultConfig.load(token, ignored -> key, originalConfig.getVaultVersion());
			});
		}

	}

	@Test
	public void testCreateNew() {
		var config = VaultConfig.createNew().cipherMode(VaultCipherMode.SIV_CTRMAC).maxFilenameLength(220).build();

		Assertions.assertNotNull(config.getId());
		Assertions.assertEquals(Constants.VAULT_VERSION, config.getVaultVersion());
		Assertions.assertEquals(VaultCipherMode.SIV_CTRMAC, config.getCiphermode());
		Assertions.assertEquals(220, config.getMaxFilenameLength());
	}

	@Test
	public void testLoadExisting() throws KeyLoadingFailedException, VaultConfigLoadException {
		var decodedJwt = Mockito.mock(DecodedJWT.class);
		var formatClaim = Mockito.mock(Claim.class);
		var ciphermodeClaim = Mockito.mock(Claim.class);
		var maxFilenameLenClaim = Mockito.mock(Claim.class);
		var keyLoader = Mockito.mock(KeyLoader.class);
		var verification = Mockito.mock(Verification.class);
		var verifier = Mockito.mock(JWTVerifier.class);
		Mockito.when(decodedJwt.getKeyId()).thenReturn("key-id");
		Mockito.when(decodedJwt.getClaim("format")).thenReturn(formatClaim);
		Mockito.when(decodedJwt.getClaim("ciphermode")).thenReturn(ciphermodeClaim);
		Mockito.when(decodedJwt.getClaim("maxFilenameLen")).thenReturn(maxFilenameLenClaim);
		Mockito.when(keyLoader.loadKey("key-id")).thenReturn(new byte[64]);
		Mockito.when(verification.withClaim("format", 42)).thenReturn(verification);
		Mockito.when(verification.build()).thenReturn(verifier);
		Mockito.when(verifier.verify(decodedJwt)).thenReturn(decodedJwt);
		Mockito.when(formatClaim.asInt()).thenReturn(42);
		Mockito.when(ciphermodeClaim.asString()).thenReturn("SIV_CTRMAC");
		Mockito.when(maxFilenameLenClaim.asInt()).thenReturn(220);
		try (var jwtMock = Mockito.mockStatic(JWT.class)) {
			jwtMock.when(() -> JWT.decode("jwt-vault-config")).thenReturn(decodedJwt);
			jwtMock.when(() -> JWT.require(Mockito.any())).thenReturn(verification);

			var config = VaultConfig.load("jwt-vault-config", keyLoader, 42);
			Assertions.assertNotNull(config);
			Assertions.assertEquals(42, config.getVaultVersion());
		}
	}

}