package org.cryptomator.cryptofs.health;

import org.cryptomator.cryptofs.health.api.HealthCheck;

import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

public class HealthChecks {

	private static final Collection<HealthCheck> ALL_CHECKS = List.of();

	public static Collection<HealthCheck> getApplicable(int vaultVersion) {
		return ALL_CHECKS.stream().filter(c -> c.isApplicable(vaultVersion)).collect(Collectors.toList());
	}

}
