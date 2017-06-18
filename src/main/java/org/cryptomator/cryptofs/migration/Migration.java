/*******************************************************************************
 * Copyright (c) 2017 Skymatic UG (haftungsbeschränkt).
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE file.
 *******************************************************************************/
package org.cryptomator.cryptofs.migration;

enum Migration {
	/**
	 * @deprecated for testing only
	 */
	@Deprecated ZERO_TO_ONE(0),

	/**
	 * Migrates vault format 5 to 6.
	 */
	FIVE_TO_SIX(5);

	private final int applicableVersion;

	private Migration(int applicableVersion) {
		this.applicableVersion = applicableVersion;
	}

	public boolean isApplicable(int version) {
		return version == applicableVersion;
	}

}
