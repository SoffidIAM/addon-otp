package com.soffid.iam.addons.otp.common;

import com.soffid.mda.annotation.ValueObject;

@ValueObject
public class OtpAuthenticationRequest {
	Long id;
	
	boolean complete;
	
	boolean timedOut;
}
