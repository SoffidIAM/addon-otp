package com.soffid.iam.addons.otp.service.impl;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Date;
import java.util.concurrent.TimeUnit;

import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base32;

import com.soffid.iam.addons.otp.common.OtpConfig;
import com.soffid.iam.addons.otp.common.OtpStatus;
import com.soffid.iam.addons.otp.model.OtpDeviceEntity;

import es.caib.seycon.ng.exception.InternalErrorException;

public class HotpValidationServiceImpl extends HotpValidationServiceBase {
	@Override
	protected boolean handleValidatePin(OtpDeviceEntity entity, OtpConfig cfg, String pin) throws Exception {
		if (!cfg.isAllowHotp())
			throw new InternalErrorException("HOTP is disabled by system administrator");
		
		final HmacOneTimePasswordGenerator totp =
				new HmacOneTimePasswordGenerator(entity.getDigits() == null ? 6: entity.getDigits().intValue(), 
		        		entity.getAlgorithm() == null ? "HmacSHA1": entity.getAlgorithm());

		byte buffer[] =  new Base32().decode(entity.getAuthKey());
        final Key key = new SecretKeySpec(buffer, "RAW");
        
        long lastUsed = entity.getLastUsedValue() == null? -5: entity.getLastUsedValue().longValue();
        
		// 5 minutes offset allowed
		int intValue;
		try {
			intValue = Integer.parseInt(pin);
		} catch (NumberFormatException e) {
			return false;
		}
		
		for (long i = lastUsed + 1 ; i < lastUsed + 25; i++)
		{
			if ( intValue == totp.generateOneTimePassword(key, i))
			{
				entity.setLastUsedValue( i);
				entity.setLastUsed(new Date());
				entity.setFails(0);
				getOtpDeviceEntityDao().update(entity);
				return true;
			}
		}
		entity.setFails(entity.getFails() + 1);
		if (entity.getFails() > 10)
			entity.setStatus(OtpStatus.LOCKED);
		getOtpDeviceEntityDao().update(entity);
		return false;
	}

	@Override
	protected byte[] handleGenerateKey(OtpDeviceEntity entity, OtpConfig cfg) throws Exception {
		if (!cfg.isAllowHotp())
			throw new InternalErrorException("HOTP is disabled by system administrator");

		SecureRandom sr = new SecureRandom();
		byte b[] = new byte[ cfg.getHotpAlgorithm().equalsIgnoreCase("HmacSHA1") ? 16: 32];
		sr.nextBytes(b);
		String s = new Base32().encodeAsString(b);
		entity.setAuthKey(s);
		entity.setAlgorithm( cfg.getHotpAlgorithm());
		entity.setDigits(cfg.getHotpDigits());
		return b;
	}

}
