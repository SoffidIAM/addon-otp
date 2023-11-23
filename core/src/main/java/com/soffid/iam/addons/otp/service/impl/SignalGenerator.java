package com.soffid.iam.addons.otp.service.impl;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

import org.springframework.beans.BeansException;

import com.soffid.iam.ServiceLocator;
import com.soffid.iam.addons.otp.common.OtpDeviceType;
import com.soffid.iam.addons.otp.model.OtpDeviceEntity;

public class SignalGenerator {
	final String CAEP_CREDENTIAL_CHANGE_EVENT_NAME = "https://schemas.openid.net/secevent/caep/event-type/credential-change";
	final String RISC_CREDENTIAL_COMPROMISE_EVENT_NAME = "https://schemas.openid.net/secevent/risc/event-type/credential-compromise";
	
	public void generateCredentialChangeEvent(OtpDeviceEntity credential, String action) throws Exception {
		try {
			Object ssvc = ServiceLocator.instance().getService("signalService-v2");
			Method m = ssvc.getClass().getMethod("signalUser", String.class, String.class, String[].class);
			m.invoke(ssvc, CAEP_CREDENTIAL_CHANGE_EVENT_NAME, credential.getUser().getUserName(),
					new String[]{"changeType", action,
							"friendlyName", credential.getName(),
							"credentialType", credential.getType() == OtpDeviceType.EMAIL ? "verifiable-credential" :
											  credential.getType() == OtpDeviceType.HOTP ? "app" :
											  credential.getType() == OtpDeviceType.TOTP ? "app" :
											  credential.getType() == OtpDeviceType.PIN ? "pin" :
											  credential.getType() == OtpDeviceType.SMS ? "phone-sms" : 
										      "password"
						});
		} catch (BeansException | NoSuchMethodException | SecurityException | IllegalAccessException | IllegalArgumentException e) {
			// Console version older than 3.5.10
		} catch (InvocationTargetException e) {
			if ( e.getCause() instanceof Exception)
				throw (Exception)e.getCause();
			else
				throw new RuntimeException(e);
		}
	}

	public void generateCredentialCompromiseEvent(OtpDeviceEntity credential) throws Exception {
		try {
			Object ssvc = ServiceLocator.instance().getService("signalService-v2");
			Method m = ssvc.getClass().getMethod("signalUser", String.class, String.class, String[].class);
			m.invoke(ssvc, RISC_CREDENTIAL_COMPROMISE_EVENT_NAME, credential.getUser().getUserName(),
					new String[]{"credentialType", credential.getType() == OtpDeviceType.EMAIL ? "verifiable-credential" :
											  credential.getType() == OtpDeviceType.HOTP ? "app" :
											  credential.getType() == OtpDeviceType.TOTP ? "app" :
											  credential.getType() == OtpDeviceType.PIN ? "pin" :
											  credential.getType() == OtpDeviceType.SMS ? "phone-sms" : 
										      "password"
						});
		} catch (BeansException | NoSuchMethodException | SecurityException | IllegalAccessException | IllegalArgumentException e) {
			// Console version older than 3.5.10
		} catch (InvocationTargetException e) {
			if ( e.getCause() instanceof Exception)
				throw (Exception)e.getCause();
			else
				throw new RuntimeException(e);
		}
	}
}
