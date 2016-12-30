/*
 * Copyright 2016 by floragunn UG (haftungsbeschränkt) - All rights reserved
 * 
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed here is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * 
 * This software is free of charge for non-commercial and academic use. 
 * For commercial use in a production environment you have to obtain a license 
 * from https://floragunn.com
 * 
 */

package com.floragunn.searchguard.auditlog.impl;

import org.junit.rules.TestRule;
import org.junit.runner.Description;
import org.junit.runners.model.Statement;

import com.floragunn.searchguard.auditlog.impl.AuditMessage.Category;

public class ResetCategories implements TestRule {

	@Override
	public Statement apply(final Statement base, Description description) {

		return new Statement() {
			@Override
			public void evaluate() throws Throwable {
				base.evaluate();
				resetCategories();
				System.setOut(System.out);
			}
		};
	}
	
	public void resetCategories() {
		for (Category category : AuditMessage.Category.values()) {
			category.setEnabled(true);
		}
	}
}
