package com.floragunn.searchguard.auditlog;

import java.io.ByteArrayOutputStream;
import java.io.FileDescriptor;
import java.io.FileOutputStream;
import java.io.PrintStream;

import org.junit.rules.TestRule;
import org.junit.runner.Description;
import org.junit.runners.model.Statement;

public class CaptureSystemOut implements TestRule {

	private ByteArrayOutputStream outContent = new ByteArrayOutputStream();
 
	
	@Override
	public Statement apply(final Statement base, Description description) {
		
	    return new Statement() {
	        @Override
	        public void evaluate() throws Throwable {	          
	          System.setOut(new PrintStream(outContent));
	          base.evaluate();
	          // http://stackoverflow.com/questions/5339499/resetting-standard-output-stream
	          System.setOut(new PrintStream(new FileOutputStream(FileDescriptor.out)));
	        }
	      };
	}
		
	public String getResult() {
		String result = outContent.toString();
		outContent = new ByteArrayOutputStream();
		System.setOut(new PrintStream(outContent));
		return result;
	}
}
