package com.soffid.iam.addons.otp.common;

import com.soffid.mda.annotation.Enumeration;

@Enumeration
public class OtpDeviceType {
	public static String TOTP = "TOTP";
	public static String HOTP = "HOTP";
	public static String EMAIL = "EMAIL";
	public static String SMS = "SMS";
}
