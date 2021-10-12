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
import com.soffid.iam.addons.otp.common.OtpDevice;
import com.soffid.iam.addons.otp.common.OtpStatus;
import com.soffid.iam.addons.otp.model.OtpDeviceEntity;

import es.caib.seycon.ng.exception.InternalErrorException;

public class TotpValidationServiceImpl extends TotpValidationServiceBase {
	@Override
	protected boolean handleValidatePin(OtpDeviceEntity entity, OtpConfig cfg, String pin) throws Exception {
		if (!cfg.isAllowTotp())
			throw new InternalErrorException("TOTP is disabled by system administrator");

		final HmacOneTimePasswordGenerator totp =
                new HmacOneTimePasswordGenerator(cfg.getTotpDigits(), cfg.getTotpAlgorithm());

		byte buffer[] =  new Base32().decode(entity.getAuthKey());
        final Key key = new SecretKeySpec(buffer, "RAW");
        long now = System.currentTimeMillis();
        now = now - now % 30000; 
        
        long lastUsed = entity.getLastUsedValue() == null? 0: entity.getLastUsedValue().longValue();
        
		// 5 minutes offset allowed
		int intValue = Integer.parseInt(pin);
		long seq = System.currentTimeMillis() / 30000L;
		
		for (long i = seq - 10; i < seq + 10; i++)
		{
			if ( i > lastUsed && intValue == totp.generateOneTimePassword(key, i))
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
		if (!cfg.isAllowTotp())
			throw new InternalErrorException("TOTP is disabled by system administrator");

		SecureRandom sr = new SecureRandom();
		byte b[] = new byte[ cfg.getTotpAlgorithm().equalsIgnoreCase("HmacSHA1") ? 16: 32];
		sr.nextBytes(b);
		String s = new Base32().encodeAsString(b);
		entity.setAuthKey(s);
		return b;
	}

}
