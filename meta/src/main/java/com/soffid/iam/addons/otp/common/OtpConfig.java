//
// (C) 2013 Soffid
// 
// This file is licensed by Soffid under GPL v3 license
//

package com.soffid.iam.addons.otp.common;
import com.soffid.mda.annotation.*;

@ValueObject 
public class OtpConfig {
	public boolean allowSms;
	
	public boolean allowVoice;

	public boolean allowTotp;
	
	public boolean allowHotp;
	
	public boolean allowEmail;
	
	public boolean allowPin;

	@Nullable
	public String smsUrl;
	@Nullable
	public String smsMethod;
	@Nullable
	public String smsBody;
	@Nullable
	public String smsHeaders;
	@Nullable
	public String smsResponseToCheck;
	@Nullable public Integer smsDigits;
	@Nullable public Integer smsLock;
	
	@Nullable
	public String voiceUrl;
	@Nullable
	public String voiceMethod;
	@Nullable
	public String voiceBody;
	@Nullable
	public String voiceHeaders;
	@Nullable
	public String voiceResponseToCheck;

	@Nullable public String emailSubject;
	@Nullable public String emailBody;
	@Nullable public Integer emailDigits;
	@Nullable public Integer emailLock;
	
	@Nullable public Integer totpDigits;
	@Nullable public String totpAlgorithm;
	@Nullable public String totpIssuer;
	@Nullable public Integer totpLock;
	
	@Nullable public Integer hotpDigits;
	@Nullable public String hotpAlgorithm;
	@Nullable public String hotpIssuer;
	@Nullable public Integer hotpLock;


	@Nullable public Integer pinLength;
	@Nullable public Integer pinDigits;
	@Nullable public Integer pinLock;
}
