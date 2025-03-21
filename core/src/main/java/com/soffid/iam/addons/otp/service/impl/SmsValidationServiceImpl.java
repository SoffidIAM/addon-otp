package com.soffid.iam.addons.otp.service.impl;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Collection;
import java.util.Date;
import java.util.concurrent.TimeUnit;

import javax.crypto.spec.SecretKeySpec;
import javax.ws.rs.core.Response;

import org.apache.commons.beanutils.PropertyUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.cxf.jaxrs.client.WebClient;
import org.apache.http.HttpStatus;
import org.json.JSONStringer;

import com.soffid.iam.addons.otp.common.OtpConfig;
import com.soffid.iam.addons.otp.common.OtpDevice;
import com.soffid.iam.addons.otp.common.OtpStatus;
import com.soffid.iam.addons.otp.model.OtpDeviceEntity;
import com.soffid.iam.api.Password;
import com.soffid.iam.api.User;
import com.soffid.iam.model.UserDataEntity;
import com.soffid.iam.model.UserEntity;
import com.soffid.iam.utils.ConfigurationCache;

import es.caib.seycon.ng.exception.InternalErrorException;

public class SmsValidationServiceImpl extends SmsValidationServiceBase {
	Log log = LogFactory.getLog(getClass());
	
	@Override
	protected boolean handleValidatePin(OtpDeviceEntity entity, OtpConfig cfg, String pin) throws Exception {
		if (!cfg.isAllowSms())
			throw new InternalErrorException("SMS OTP is disabled by system administrator");
		Password p = Password.decode(entity.getAuthKey());
		if (pin.equals(p.getPassword())) {
			entity.setLastUsed(new Date());
			entity.setFails(0);
			entity.setAuthKey(null);
			if (entity.getStatus() == OtpStatus.CREATED)
				entity.setStatus(OtpStatus.VALIDATED);
			updateInNewTransaction(entity);
			return true;
		} else {
			entity.setFails(entity.getFails() + 1);
			if (entity.getFails() > cfg.getSmsLock() && entity.getStatus() != OtpStatus.LOCKED) { 
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
	protected void handleSendPin(OtpDeviceEntity device, OtpConfig cfg) throws Exception {
		if (!cfg.isAllowSms() && ! cfg.isAllowVoice())
			throw new InternalErrorException("SMS OTP is disabled by system administrator");
		
		if (device.getLastIssued() != null &&
				(device.getLastUsed() == null || device.getLastUsed().before(device.getLastIssued())) &&
				(device.getLastIssued().getTime() > System.currentTimeMillis() - 60000) &&
				device.getFails() < 3) {
			// Use already sent SMS
			return;
		}
		SecureRandom sr = new SecureRandom();
		String pin = "";
		for (int i = 0; i < cfg.getSmsDigits(); i++) {
			pin += (char) ('0'+sr.nextInt(10));
		}
		device.setAuthKey(new Password(pin).toString());
		device.setFails(0);
		device.setLastIssued(new Date());
		getOtpDeviceEntityDao().update(device);

		send(device, cfg, pin, ! cfg.isAllowSms());
	}

	protected void send(OtpDeviceEntity device, OtpConfig cfg, String pin, boolean voice)
			throws UnsupportedEncodingException, InternalError, IOException, InternalErrorException {
		String pin2;
		
		if (voice) {
			pin2 = "";
			for (int i = 0; i < pin.length(); i++)
				pin2 += pin.substring(i, i+1)+". ";
		}
		else
			pin2 = pin;

		String smsUrl = voice ? cfg.getVoiceUrl(): cfg.getSmsUrl();
		final String url = translate(smsUrl, device, pin2, true, false);
		WebClient request = WebClient.create(url);
		
		boolean encode = true;
		boolean json = false;
		String smsHeaders = voice ? cfg.getVoiceHeaders(): cfg.getSmsHeaders();
		if (smsHeaders != null) {
			for (String line: smsHeaders.split("\n")) {
				line = line.trim();
				if ( !line.isEmpty()) {
					int i = line.indexOf(':');
					String tag = line.substring(0,i).trim();
					String value = line.substring(i+1).trim();
					if (!tag.isEmpty() && !value.isEmpty()) {
						if (tag.equalsIgnoreCase("content-type") && ! value.contains("application/x-www-form-urlencoded"))
							encode = false;
						if (tag.equalsIgnoreCase("content-type") && value.contains("application/json"))
							json = true;
						request.header(tag, value);
					}
				}
			}
		}
		log.info("Sending message to "+device.getUser().getUserName());
		String smsMethod = voice? cfg.getVoiceMethod(): cfg.getSmsMethod();
		String smsBody = translate(voice? cfg.getVoiceBody(): cfg.getSmsBody(), device, pin2, encode, json);
		Response response = request.invoke(smsMethod, smsBody);

		if ( response.getStatus() != HttpStatus.SC_OK)
			throw new InternalError ("Error sending SMS message: HTTP/"+response.getStatus());
		InputStream in = (InputStream) response.getEntity();
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		int read;
		while ((read = in.read()) >= 0)
			out.write(read);
		String smsResponseCheck = voice? cfg.getVoiceResponseToCheck(): cfg.getSmsResponseToCheck();
		if (smsResponseCheck != null) {
			if (!out.toString("UTF-8").contains(smsResponseCheck)) {
				log.info("Error sending SMS:\n"+
						smsMethod+" "+url+"\n"+
						smsHeaders + "\n\n" +
						smsBody);
				log.info("SMS gateway response:\n"+out.toString("UTF-8"));
				throw new InternalErrorException(voice? "Cannot send voice message": "Cannot send SMS message");
			}
		}
	}


	private String translate(String smsBody, OtpDeviceEntity device, String pin, boolean encode, boolean json) throws UnsupportedEncodingException {
		StringBuffer b = new StringBuffer();
		int pos = 0;
		do {
			int next = smsBody.indexOf("${", pos);
			if (next < 0) { 
				b.append(smsBody.substring(pos));
				break;
			} else {
				int last = smsBody.indexOf("}", next);
				if (last < 0) {
					b.append(smsBody.substring(pos));
					break;
				}
				String tag = smsBody.substring(next+2, last);
				Object value = eval (tag, device, pin);
				b.append(smsBody.substring(pos, next));
				if (value != null) 
					b.append( encode ? URLEncoder.encode(value.toString(), "UTF-8") :
						json? value.toString().replace("\\", "\\\\").replace("\"", "\\\""):
						value.toString());
				pos = last + 1;
			}
		} while (true);
		return b.toString();
	}
	
	private Object eval(String tag, OtpDeviceEntity device, String pin) {
		Object value = null;
		
		if (tag.equals("PIN"))
			return pin;
		if (tag.equals("PHONE"))
			return device.getPhone();
		Collection<UserDataEntity> list = getUserDataEntityDao().findByDataType(device.getUser().getUserName(), tag);
		if (list.isEmpty()) {
			UserEntity userEntity = device.getUser();
			if (userEntity != null) {
				User user = getUserEntityDao().toUser(userEntity);
				try {
					value = PropertyUtils.getProperty(user, tag);
				} catch (Exception e) {
				}
			}
		} else {
			value = list.iterator().next().getObjectValue();
		}
		return value;
	}

	@Override
	protected void handleResend(OtpDeviceEntity device, OtpConfig cfg, boolean voice) throws Exception {
		if (!cfg.isAllowSms() && ! cfg.isAllowVoice())
			throw new InternalErrorException("SMS OTP is disabled by system administrator");
		
		if (device.getAuthKey() == null) {
			return;
		}
		String pin = Password.decode(device.getAuthKey()).getPassword();

		send(device, cfg, pin, voice && cfg.isAllowVoice() || ! cfg.isAllowSms());
	}


}
