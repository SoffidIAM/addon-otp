package com.soffid.iam.addons.otp.service.impl;

import java.util.Comparator;
import java.util.List;

import com.soffid.iam.addons.otp.common.OtpConfig;
import com.soffid.iam.addons.otp.common.OtpDeviceType;
import com.soffid.iam.addons.otp.common.OtpStatus;
import com.soffid.iam.addons.otp.model.OtpDeviceEntity;
import com.soffid.iam.addons.otp.model.OtpDeviceEntityDao;
import com.soffid.iam.addons.otp.service.OtpService;
import com.soffid.iam.api.Challenge;
import com.soffid.iam.service.impl.OTPHandler;

import es.caib.seycon.ng.exception.InternalErrorException;

public class InternalOTPHandler implements OTPHandler {

	private HotpValidationService hotpValidationService;
	private TotpValidationService totpValidationService;
	private EmailValidationService emailValidationService;
	private SmsValidationService smsValidationService;
	private PinValidationService pinValidationService;
	private OtpDeviceEntityDao otpDeviceEntityDao;
	private OtpService otpService;

	public Challenge selectToken(Challenge challenge) throws Exception {
		List<OtpDeviceEntity> token = otpDeviceEntityDao.findEnabledByUser(challenge.getUser().getUserName());
		if (token == null || token.isEmpty())
			return null;
		token.sort(new Comparator<OtpDeviceEntity>() {
			public int compare(OtpDeviceEntity o1, OtpDeviceEntity o2) {
				return o2.getCreated().compareTo(o1.getCreated());
			}
		});
		
		for (OtpDeviceEntity entity: token) {
			if (isCompatible(entity.getType(), challenge.getOtpHandler())) {
				challenge.setCardNumber(entity.getName());
				challenge.setCell("PIN");
				final OtpConfig cfg = otpService.getConfiguration();
				if (entity.getType() == OtpDeviceType.EMAIL)
					emailValidationService.sendPin(entity, cfg);
				if (entity.getType() == OtpDeviceType.SMS) {
					smsValidationService.sendPin(entity, cfg);
					challenge.setAlternativeMethodAvailable(cfg.isAllowVoice());
					challenge.setResendAvailable(true);
				}
				if (entity.getType() == OtpDeviceType.PIN) {
					String pattern = pinValidationService.selectDigits(entity, cfg);
					if (pattern != null)
						challenge.setCell("digits "+pattern);
				}
				return challenge;
			}			
		}
		return null;
	}

	private boolean isCompatible(OtpDeviceType type, String otpHandler) {
		if (otpHandler == null || otpHandler.trim().isEmpty())
			return true;
		if (type == OtpDeviceType.SMS)
			return otpHandler.toUpperCase().contains("SMS");
			
		if (type == OtpDeviceType.EMAIL) 
			return otpHandler.toUpperCase().contains("EMAIL");

		if (type == OtpDeviceType.TOTP || type == OtpDeviceType.HOTP)
			return otpHandler.toUpperCase().contains("OTP");

		if (type == OtpDeviceType.PIN)
			return otpHandler.toUpperCase().contains("PIN");

		return false;
	}

	public boolean validatePin(Challenge challenge, String pin) throws Exception {
		List<OtpDeviceEntity> token = otpDeviceEntityDao.findEnabledByUser(challenge.getUser().getUserName());
		if (token == null || token.isEmpty())
			return false;
		token.sort(new Comparator<OtpDeviceEntity>() {
			public int compare(OtpDeviceEntity o1, OtpDeviceEntity o2) {
				return o2.getCreated().compareTo(o1.getCreated());
			}
		});
		
		for (OtpDeviceEntity entity: token) {
			if (entity.getName().equals(challenge.getCardNumber())) {
				if (entity.getType() == OtpDeviceType.EMAIL)
					return emailValidationService.validatePin(entity, otpService.getConfiguration(), pin);
				if (entity.getType() == OtpDeviceType.SMS)
					return smsValidationService.validatePin(entity, otpService.getConfiguration(), pin);
				if (entity.getType() == OtpDeviceType.HOTP)
					return hotpValidationService.validatePin(entity, otpService.getConfiguration(), pin);
				if (entity.getType() == OtpDeviceType.TOTP)
					return totpValidationService.validatePin(entity, otpService.getConfiguration(), pin);
				if (entity.getType() == OtpDeviceType.PIN)
					return pinValidationService.validatePin(entity, otpService.getConfiguration(), pin);
			}			
		}
		return false;
	}

	public String generateTypeForAudit(Challenge challenge) throws Exception {
		List<OtpDeviceEntity> token = otpDeviceEntityDao.findEnabledByUser(challenge.getUser().getUserName());
		if (token == null || token.isEmpty())
			return null;
		token.sort(new Comparator<OtpDeviceEntity>() {
			public int compare(OtpDeviceEntity o1, OtpDeviceEntity o2) {
				return o2.getCreated().compareTo(o1.getCreated());
			}
		});
		for (OtpDeviceEntity entity: token) {
			if (entity.getName().equals(challenge.getCardNumber())) {
				if (entity.getType() == OtpDeviceType.EMAIL)
					return "M";
				if (entity.getType() == OtpDeviceType.SMS)
					return "S";
				if (entity.getType() == OtpDeviceType.HOTP)
					return "O";
				if (entity.getType() == OtpDeviceType.TOTP)
					return "O";
				if (entity.getType() == OtpDeviceType.PIN)
					return "I";
			}
		}
		return "?";
	}

	public boolean resetFailCount(String account) throws Exception {
		List<OtpDeviceEntity> token = otpDeviceEntityDao.findEnabledByUser(account);
		if (token == null || token.isEmpty())
			return false;
		
		for (OtpDeviceEntity entity: token) {
			entity.setFails(0);
			otpDeviceEntityDao.update(entity);
		}
		return false;
	}

	public void setHotpValidationService(HotpValidationService hotpValidationService) {
		this.hotpValidationService = hotpValidationService;
	}

	public void setTotpValidationService(TotpValidationService totpValidationService) {
		this.totpValidationService = totpValidationService;
	}

	public void setEmailValidationService(EmailValidationService emailValidationService) {
		this.emailValidationService = emailValidationService;
	}

	public void setSmsValidationService(SmsValidationService smsValidationService) {
		this.smsValidationService = smsValidationService;
	}

	public void setOtpDeviceEntityDao(OtpDeviceEntityDao otpDeviceEntityDao) {
		this.otpDeviceEntityDao = otpDeviceEntityDao;
	}

	public OtpService getOtpService() {
		return otpService;
	}

	public void setOtpService(OtpService otpService) {
		this.otpService = otpService;
	}

	public PinValidationService getPinValidationService() {
		return pinValidationService;
	}

	public void setPinValidationService(PinValidationService pinValidationService) {
		this.pinValidationService = pinValidationService;
	}

	@Override
	public Challenge resendToken(Challenge challenge, boolean alternativeMethod) throws Exception {
		List<OtpDeviceEntity> token = otpDeviceEntityDao.findEnabledByUser(challenge.getUser().getUserName());
		if (token == null || token.isEmpty())
			return challenge;
		token.sort(new Comparator<OtpDeviceEntity>() {
			public int compare(OtpDeviceEntity o1, OtpDeviceEntity o2) {
				return o2.getCreated().compareTo(o1.getCreated());
			}
		});
		
		for (OtpDeviceEntity entity: token) {
			if (entity.getName().equals(challenge.getCardNumber())) {
				if (entity.getType() == OtpDeviceType.SMS) {
					smsValidationService.resend(entity, otpService.getConfiguration(), alternativeMethod);
				}
			}			
		}
		return challenge;
	}

}
