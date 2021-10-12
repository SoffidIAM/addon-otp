package com.soffid.iam.addons.otp.common;

import com.soffid.mda.annotation.Enumeration;

@Enumeration
public class OtpStatus {
	public static String CREATED="C";
	public static String VALIDATED="V";
	public static String LOCKED="L";
	public static String DISABLED="D";
}
