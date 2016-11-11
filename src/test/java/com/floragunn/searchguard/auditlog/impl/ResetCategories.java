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
