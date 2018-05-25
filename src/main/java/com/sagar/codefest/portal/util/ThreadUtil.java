package com.sagar.codefest.portal.util;

public class ThreadUtil {
	public static void sleepQuietly(int millis) {
		try {
			Thread.sleep(millis);
		} catch (Exception e) {

		}
	}
}
