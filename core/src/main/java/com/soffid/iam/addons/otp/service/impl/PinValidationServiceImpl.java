package com.soffid.iam.addons.otp.service.impl;

import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Date;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import com.soffid.iam.addons.otp.common.OtpConfig;
import com.soffid.iam.addons.otp.common.OtpStatus;
import com.soffid.iam.addons.otp.model.OtpDeviceEntity;
import com.soffid.iam.api.Password;

import es.caib.seycon.ng.exception.InternalErrorException;

public class PinValidationServiceImpl extends PinValidationServiceBase {
	Log log = LogFactory.getLog(getClass());
	
	@Override
	protected boolean handleValidatePin(OtpDeviceEntity entity, OtpConfig cfg, String pin) throws Exception {
		if (!cfg.isAllowPin())
			throw new InternalErrorException("PIN OTP is disabled by system administrator");
		MessageDigest md = MessageDigest.getInstance("SHA-1");
		byte[] digest = md.digest(pin.trim().getBytes("UTF-8"));
		if (Base64.getEncoder().encodeToString(digest).equals(entity.getAuthKey())) {
			entity.setLastUsed(new Date());
			entity.setFails(0);
			entity.setAuthKey(null);
			updateInNewTransaction(entity);
			return true;
		} else {
			entity.setFails(entity.getFails() + 1);
			if (entity.getFails() > cfg.getPinLock() && entity.getStatus() != OtpStatus.LOCKED) { 
				new SignalGenerator().generateCredentialCompromiseEvent(entity);
				try {
					IssueHelper.lockOtp(entity.getUser().getId(), entity.getName());
				} catch (Exception e) {
					// Old version
				}
				entity.setStatus(OtpStatus.LOCKED);
			}
			updateInNewTransaction(entity);
			return false;
		}
	}

	protected void updateInNewTransaction(OtpDeviceEntity entity) throws InternalErrorException, InterruptedException {
		UpdateUtil.update(getOtpDeviceEntityDao(), entity, getAsyncRunnerService());
	}

	@Override
	protected String handleSelectDigits(OtpDeviceEntity device, OtpConfig cfg) throws Exception {
		final String box = "\u25a2";
		final String square = "\u25a3";
		final char one = '\u2460';
		
		if (!cfg.isAllowPin())
			throw new InternalErrorException("PIN OTP is disabled by system administrator");
		
		String pin = Password.decode(device.getPin()).getPassword();
		char ach[] = pin.toCharArray();
		int digits = pin.length();
		SecureRandom random = new SecureRandom();
		while (cfg.getPinDigits().intValue() < digits) {
			int r = random.nextInt(pin.length());
			if (ach[r] != '\0') {
				ach[r] = '\0';
				digits --;
			}
		}
		String result = "";
		String hint = "";
		for (int i = 0; i < ach.length; i++ ) {
			if (ach[i] == '\0') {
				hint += square;;
			}
			else if (ach.length <= 10) {
				hint += (char) (i+one);
				result += ach[i];
			} else {
				hint += box;
				result += ach[i];
			}
		}
		MessageDigest md = MessageDigest.getInstance("SHA-1");
		byte[] digest = md.digest(result.getBytes("UTF-8"));
		device.setAuthKey(Base64.getEncoder().encodeToString(digest));
		getOtpDeviceEntityDao().update(device);

		if (hint.contains(square))
			return hint;
		else
			return null;
	}


}
