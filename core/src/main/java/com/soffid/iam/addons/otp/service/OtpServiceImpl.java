package com.soffid.iam.addons.otp.service;

import java.awt.image.BufferedImage;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Collection;
import java.util.Date;
import java.util.LinkedList;
import java.util.List;

import org.apache.commons.codec.binary.Base32;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.qrcode.QRCodeWriter;
import com.soffid.iam.addons.otp.common.OtpConfig;
import com.soffid.iam.addons.otp.common.OtpDevice;
import com.soffid.iam.addons.otp.common.OtpDeviceType;
import com.soffid.iam.addons.otp.common.OtpStatus;
import com.soffid.iam.addons.otp.model.OtpDeviceEntity;
import com.soffid.iam.addons.otp.model.OtpDeviceEntityDao;
import com.soffid.iam.api.AsyncList;
import com.soffid.iam.api.Challenge;
import com.soffid.iam.api.Configuration;
import com.soffid.iam.api.PagedResult;
import com.soffid.iam.api.Password;
import com.soffid.iam.bpm.service.scim.ScimHelper;
import com.soffid.iam.model.ConfigEntity;
import com.soffid.iam.model.criteria.CriteriaSearchConfiguration;
import com.soffid.iam.utils.AutoritzacionsUsuari;
import com.soffid.iam.utils.ConfigurationCache;
import com.soffid.iam.utils.Security;

import es.caib.seycon.ng.exception.InternalErrorException;

public class OtpServiceImpl extends OtpServiceBase {

	@Override
	protected void handleCancelDevice(OtpDevice device) throws Exception {
		OtpDeviceEntity entity = getOtpDeviceEntityDao().load(device.getId());
		if (entity != null) {
			entity.setStatus(OtpStatus.DISABLED);
			getOtpDeviceEntityDao().update(entity);
		}
	}

	@Override
	protected OtpDevice handleRegisterDevice(String user, OtpDevice device) throws Exception {
		BufferedImage image = null;
		OtpDeviceEntity entity = getOtpDeviceEntityDao().newOtpDeviceEntity();
		entity.setCreated(new Date());
		entity.setUser(getUserEntityDao().findByUserName(user));
		if (entity.getUser() == null)
			throw new InternalErrorException(Messages.getString("OtpServiceImpl.0")+user); //$NON-NLS-1$
		entity.setFails(0);
		entity.setStatus(OtpStatus.VALIDATED);
		entity.setType(device.getType());
		if (device.getStatus() != OtpStatus.VALIDATED)
			entity.setStatus(OtpStatus.CREATED);
		else
			entity.setStatus(OtpStatus.VALIDATED);
		entity.setCreated(new Date());
		if (device.getType() == OtpDeviceType.EMAIL) {
			if (device.getEmail() == null || device.getEmail().trim().isEmpty())
				throw new InternalErrorException(Messages.getString("OtpServiceImpl.1")); //$NON-NLS-1$
			char[] ach = device.getEmail().toCharArray();
			int step = 0;
			for (int i = 0; i < ach.length; i++)
			{
				if (ach[i] == '.' || ach[i] == '@') step = 0;
				else if (step ++ >= 2) ach[i] = '*';
			}
			entity.setEmail(device.getEmail());
			entity.setName(Messages.getString("OtpServiceImpl.11")+new String(ach)); //$NON-NLS-1$
		}
		if (device.getType() == OtpDeviceType.SMS) {
			if (device.getPhone() == null || device.getPhone().trim().isEmpty())
				throw new InternalErrorException(Messages.getString("OtpServiceImpl.12")); //$NON-NLS-1$
			char[] ach = device.getPhone().toCharArray();
			int step = 0;
			for (int i = 2; i < ach.length - 2; i++)
			{
				ach[i] = '*';
			}
			entity.setPhone(device.getPhone());
			entity.setName(Messages.getString("OtpServiceImpl.4")+new String(ach)); //$NON-NLS-1$
		}
		if (device.getType() == OtpDeviceType.TOTP) {
			String last = getTokenId("TOTP"); //$NON-NLS-1$
			entity.setName(last);
			byte[] key = getTotpValidationService().generateKey(entity, handleGetConfiguration() );
			image = generateTotpQR(entity, key);
		}
		if (device.getType() == OtpDeviceType.HOTP) {
			String last = getTokenId("HOTP"); //$NON-NLS-1$
			entity.setName(last);
			byte[] key = getHotpValidationService().generateKey(entity, handleGetConfiguration());
			image = generateHotpQR(entity, key);
		}
		if (device.getType() == OtpDeviceType.PIN) {
			OtpConfig cfg = handleGetConfiguration();
			if (device.getPin().getPassword().length() < cfg.getPinLength())
				throw new InternalErrorException(String.format(Messages.getString("OtpServiceImpl.16"), cfg.getPinLength())); //$NON-NLS-1$
			entity.setName(Messages.getString("OtpServiceImpl.17")); //$NON-NLS-1$
			entity.setPin(device.getPin().toString());
		}
		getOtpDeviceEntityDao().create(entity);
		device = getOtpDeviceEntityDao().toOtpDevice(entity);
		device.setImage(image);
		return device;
	}

	public static byte[] hexStringToByteArray(String s) {
	    int len = s.length();
	    byte[] data = new byte[len / 2];
	    for (int i = 0; i < len; i += 2) {
	        data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
	                             + Character.digit(s.charAt(i+1), 16));
	    }
	    return data;
	}

	@Override
	protected OtpDevice handleImportDevice(String user, OtpDevice device, String secret) throws Exception {
		OtpDeviceEntity entity = getOtpDeviceEntityDao().newOtpDeviceEntity();
		entity.setCreated(new Date());
		entity.setUser(getUserEntityDao().findByUserName(user));
		if (entity.getUser() == null)
			throw new InternalErrorException(Messages.getString("OtpServiceImpl.0")+user); //$NON-NLS-1$
		entity.setFails(0);
		entity.setStatus(OtpStatus.VALIDATED);
		entity.setType(device.getType());
		entity.setName(device.getName());
		if (device.getStatus() != OtpStatus.VALIDATED)
			entity.setStatus(OtpStatus.CREATED);
		else
			entity.setStatus(OtpStatus.VALIDATED);
		entity.setCreated(new Date());
		if (device.getType() == OtpDeviceType.EMAIL) {
			if (device.getEmail() == null || device.getEmail().trim().isEmpty())
				throw new InternalErrorException(Messages.getString("OtpServiceImpl.1")); //$NON-NLS-1$
			char[] ach = device.getEmail().toCharArray();
			int step = 0;
			for (int i = 0; i < ach.length; i++)
			{
				if (ach[i] == '.' || ach[i] == '@') step = 0;
				else if (step ++ >= 2) ach[i] = '*';
			}
			entity.setEmail(device.getEmail());
			entity.setName(Messages.getString("OtpServiceImpl.11")+new String(ach)); //$NON-NLS-1$
		}
		if (device.getType() == OtpDeviceType.SMS) {
			if (device.getPhone() == null || device.getPhone().trim().isEmpty())
				throw new InternalErrorException(Messages.getString("OtpServiceImpl.12")); //$NON-NLS-1$
			char[] ach = device.getPhone().toCharArray();
			int step = 0;
			for (int i = 2; i < ach.length - 2; i++)
			{
				ach[i] = '*';
			}
			entity.setPhone(device.getPhone());
			entity.setName(Messages.getString("OtpServiceImpl.13")+new String(ach)); //$NON-NLS-1$
		}
		if (device.getType() == OtpDeviceType.TOTP) {
			String last = getTokenId("TOTP"); //$NON-NLS-1$
			OtpConfig cfg = handleGetConfiguration();
			entity.setAuthKey(new Base32().encodeAsString(hexStringToByteArray(secret)));
			entity.setAlgorithm( cfg.getTotpAlgorithm());
			entity.setDigits(cfg.getTotpDigits());
		}
		if (device.getType() == OtpDeviceType.HOTP) {
			String last = getTokenId("HOTP"); //$NON-NLS-1$
			OtpConfig cfg = handleGetConfiguration();
			entity.setAuthKey(new Base32().encodeAsString(hexStringToByteArray(secret)));
			entity.setAlgorithm( cfg.getHotpAlgorithm());
			entity.setDigits(cfg.getHotpDigits());
		}
		if (device.getType() == OtpDeviceType.PIN) {
			OtpConfig cfg = handleGetConfiguration();
			if (device.getPin().getPassword().length() < cfg.getPinLength())
				throw new InternalErrorException(String.format(Messages.getString("OtpServiceImpl.16"), cfg.getPinLength())); //$NON-NLS-1$
			entity.setName(Messages.getString("OtpServiceImpl.17")); //$NON-NLS-1$
			entity.setPin(device.getPin().toString());
		}
		getOtpDeviceEntityDao().create(entity);
		return device;
	}

	private BufferedImage generateTotpQR(OtpDeviceEntity entity, byte[] key) throws Exception {
		OtpConfig cfg = handleGetConfiguration();
		String url = "otpauth://totp/"+ //$NON-NLS-1$
				URLEncoder.encode(cfg.getTotpIssuer(),"UTF-8")+ //$NON-NLS-1$
				":"+entity.getName()+" "+  //$NON-NLS-1$ //$NON-NLS-2$
				URLEncoder.encode(entity.getUser().getFullName().replace(' ', '_'), "UTF-8"); //$NON-NLS-1$
		url += "?secret="+encodeKey(key); //$NON-NLS-1$
		url += "&issuer="+ URLEncoder.encode(cfg.getTotpIssuer(), "UTF-8"); //$NON-NLS-1$ //$NON-NLS-2$
		url += "&algorithm="+URLEncoder.encode(entity.getAlgorithm().substring(4), "UTF-8"); //$NON-NLS-1$ //$NON-NLS-2$
		url += "&digits="+URLEncoder.encode(entity.getDigits().toString(), "UTF-8") ; //$NON-NLS-1$ //$NON-NLS-2$
		url += "&period=30"; //$NON-NLS-1$
		url += "&image="+URLEncoder.encode("https://www.soffid.com/favicon-150.png", "UTF-8"); //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
		
		QRCodeWriter barcodeWriter = new QRCodeWriter();
	    BitMatrix bitMatrix = 
	    	      barcodeWriter.encode(url, BarcodeFormat.QR_CODE, 200, 200);

   	    BufferedImage img = MatrixToImageWriter.toBufferedImage(bitMatrix);
   	    
   	    return img;
	}

	private BufferedImage generateHotpQR(OtpDeviceEntity entity, byte[] key) throws Exception {
		OtpConfig cfg = handleGetConfiguration();
		String url = "otpauth://hotp/"+ //$NON-NLS-1$
				URLEncoder.encode(cfg.getHotpIssuer(),"UTF-8")+ //$NON-NLS-1$
				":"+entity.getName()+" "+  //$NON-NLS-1$ //$NON-NLS-2$
				URLEncoder.encode(entity.getUser().getFullName().replace(' ', '_'), "UTF-8"); //$NON-NLS-1$
		url += "?secret="+encodeKey(key); //$NON-NLS-1$
		url += "&issuer="+ URLEncoder.encode(cfg.getHotpIssuer(), "UTF-8"); //$NON-NLS-1$ //$NON-NLS-2$
		url += "&algorithm="+URLEncoder.encode(entity.getAlgorithm().substring(4), "UTF-8"); //$NON-NLS-1$ //$NON-NLS-2$
		url += "&digits="+URLEncoder.encode(entity.getDigits().toString(), "UTF-8") ; //$NON-NLS-1$ //$NON-NLS-2$
		url += "&counter=0"; //$NON-NLS-1$
		url += "&image="+URLEncoder.encode("https://www.soffid.com/favicon-150.png", "UTF-8"); //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
		
		QRCodeWriter barcodeWriter = new QRCodeWriter();
	    BitMatrix bitMatrix = 
	    	      barcodeWriter.encode(url, BarcodeFormat.QR_CODE, 200, 200);

   	    BufferedImage img = MatrixToImageWriter.toBufferedImage(bitMatrix);
   	    
   	    return img;
	}

	protected String encodeKey(byte[] key) throws UnsupportedEncodingException {
		String s = new Base32().encodeAsString(key);
		while (s.endsWith("=")) //$NON-NLS-1$
			s = s.substring(0, s.length()-1);
		return s;
	}

	protected String getTokenId(String prefix) {
		ConfigEntity cfg = getConfigEntityDao().findByCodeAndNetworkCode("addon.otp.next-token", null); //$NON-NLS-1$
		if (cfg == null)
		{
			cfg = getConfigEntityDao().newConfigEntity();
			cfg.setDescription(Messages.getString("OtpServiceImpl.52")); //$NON-NLS-1$
			cfg.setName("addon.otp.next-token"); //$NON-NLS-1$
			cfg.setValue("1"); //$NON-NLS-1$
		}
		String last = cfg.getValue();
		String next = Integer.toString(Integer.parseInt(last)+1);
		while (last.length() < 8) last = "0"+last; //$NON-NLS-1$
		cfg.setValue(next);
		if (cfg.getId() == null)
			getConfigEntityDao().create(cfg);
		else
			getConfigEntityDao().update(cfg);
		return prefix+last;
	}

	@Override
	protected List<OtpDevice> handleFindUserDevices(String users) throws Exception {
		List<OtpDeviceEntity> l = getOtpDeviceEntityDao().findByUser(users);
		return getOtpDeviceEntityDao().toOtpDeviceList(l);
	}

	@Override
	protected void handleUnlockDevice(OtpDevice device) throws Exception {
		OtpDeviceEntity entity = getOtpDeviceEntityDao().load(device.getId());
		if (entity != null && entity.getStatus() == OtpStatus.LOCKED) {
			entity.setStatus(OtpStatus.VALIDATED);
			getOtpDeviceEntityDao().update(entity);
		}
	}

	@Override
	protected OtpConfig handleGetConfiguration() throws Exception {
		OtpConfig configuration = new OtpConfig();
		String s = null;

		configuration.setAllowEmail( "true".equals(getConfigDefault("otp.email.allow", "false"))); //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
		configuration.setEmailBody( getBlobConfigDefault("otp.email.body", Messages.getString("OtpServiceImpl.60"))); //$NON-NLS-1$ //$NON-NLS-2$
		configuration.setEmailSubject( getConfigDefault("otp.email.subject", Messages.getString("OtpServiceImpl.62"))); //$NON-NLS-1$ //$NON-NLS-2$
		configuration.setEmailDigits(Integer.decode( getConfigDefault("otp.email.digits", "6"))); //$NON-NLS-1$ //$NON-NLS-2$
		configuration.setEmailLock( Integer.decode( getConfigDefault("otp.email.lock", "10"))); //$NON-NLS-1$ //$NON-NLS-2$
		
		configuration.setAllowSms("true".equals(getConfigDefault("otp.sms.allow", "false"))); //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
		configuration.setSmsBody( getBlobConfigDefault("otp.sms.body", "")); //$NON-NLS-1$ //$NON-NLS-2$
		configuration.setSmsHeaders( getConfigDefault("otp.sms.headers", "")); //$NON-NLS-1$ //$NON-NLS-2$
		configuration.setSmsMethod( getConfigDefault("otp.sms.method", "GET")); //$NON-NLS-1$ //$NON-NLS-2$
		configuration.setSmsResponseToCheck( getConfigDefault("otp.sms.check", "")); //$NON-NLS-1$ //$NON-NLS-2$
		configuration.setSmsUrl( getConfigDefault("otp.sms.url", "https://www.ovh.com/cgi-bin/sms/http2sms.cgi?account=...&password=...&login=...&from=...&" //$NON-NLS-1$ //$NON-NLS-2$
				+ "to=${PHONE}&" //$NON-NLS-1$
				+ "message="+Messages.getString("OtpServiceImpl.14")+": ${PIN}&" //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
				+ "noStop&contentType=application/json&class=0")); //$NON-NLS-1$
		configuration.setSmsDigits(Integer.decode( getConfigDefault("otp.sms.digits", "6"))); //$NON-NLS-1$ //$NON-NLS-2$
		configuration.setSmsLock( Integer.decode( getConfigDefault("otp.sms.lock", "10"))); //$NON-NLS-1$ //$NON-NLS-2$

		configuration.setAllowVoice("true".equals(getConfigDefault("otp.voice.allow", "false"))); //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
		configuration.setVoiceBody( getBlobConfigDefault("otp.voice.body", "")); //$NON-NLS-1$ //$NON-NLS-2$
		configuration.setVoiceHeaders( getConfigDefault("otp.voice.headers", "")); //$NON-NLS-1$ //$NON-NLS-2$
		configuration.setVoiceMethod( getConfigDefault("otp.voice.method", "GET")); //$NON-NLS-1$ //$NON-NLS-2$
		configuration.setVoiceResponseToCheck( getConfigDefault("otp.voice.check", "")); //$NON-NLS-1$ //$NON-NLS-2$
		configuration.setVoiceUrl( getConfigDefault("otp.voice.url", "")); //$NON-NLS-1$

		configuration.setAllowHotp("true".equals(getConfigDefault("otp.hotp.allow", "false"))); //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
		configuration.setHotpAlgorithm(getConfigDefault("otp.hotp.algorithm", "HmacSHA1")); //$NON-NLS-1$ //$NON-NLS-2$
		configuration.setHotpDigits(Integer.decode( getConfigDefault("otp.hotp.digits", "6"))); //$NON-NLS-1$ //$NON-NLS-2$
		configuration.setHotpIssuer(getConfigDefault("otp.hotp.issuer", "Issuer")); //$NON-NLS-1$ //$NON-NLS-2$
		configuration.setHotpLock( Integer.decode( getConfigDefault("otp.hotp.lock", "10"))); //$NON-NLS-1$ //$NON-NLS-2$

		configuration.setAllowTotp("true".equals(getConfigDefault("otp.totp.allow", "false"))); //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
		configuration.setTotpAlgorithm(getConfigDefault("otp.totp.algorithm", "HmacSHA1")); //$NON-NLS-1$ //$NON-NLS-2$
		configuration.setTotpDigits(Integer.decode( getConfigDefault("otp.totp.digits", "6"))); //$NON-NLS-1$ //$NON-NLS-2$
		configuration.setTotpIssuer(getConfigDefault("otp.totp.issuer", "Issuer")); //$NON-NLS-1$ //$NON-NLS-2$
		configuration.setTotpLock( Integer.decode( getConfigDefault("otp.totp.lock", "10"))); //$NON-NLS-1$ //$NON-NLS-2$
		
		configuration.setAllowPin("true".equals(getConfigDefault("otp.pin.allow", "false"))); //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
		configuration.setPinDigits( Integer.parseInt( getConfigDefault("otp.pin.digits", "3")) ); //$NON-NLS-1$ //$NON-NLS-2$
		configuration.setPinLength( Integer.parseInt( getConfigDefault("otp.pin.length", "8"))); //$NON-NLS-1$ //$NON-NLS-2$
		configuration.setPinLock( Integer.decode( getConfigDefault("otp.pin.lock", "10"))); //$NON-NLS-1$ //$NON-NLS-2$

		return configuration;
	}

	protected String getConfigDefault(String p, String def) {
		String v = ConfigurationCache.getProperty(p);
		return v != null ? v: def;
	}

	protected String getBlobConfigDefault(String p, String def) throws InternalErrorException {
		String v = null;
		final byte[] blob = getConfigurationService().getBlob(p);
		if (blob == null)
			v = ConfigurationCache.getProperty(p);
		else
			v = new String(blob, StandardCharsets.UTF_8);
		return v != null ? v: def;
	}

	@Override
	protected void handleUpdate(OtpConfig config) throws Exception {
		updateConfig("otp.email.allow", Boolean.toString(config.isAllowEmail())); //$NON-NLS-1$
		updateBlobConfig("otp.email.body", config.getEmailBody()); //$NON-NLS-1$
		updateConfig("otp.email.subject", config.getEmailSubject()); //$NON-NLS-1$
		updateConfig("otp.email.digits", config.getEmailDigits()); //$NON-NLS-1$
		updateConfig("otp.email.lock", config.getEmailLock()); //$NON-NLS-1$
		
		updateConfig("otp.sms.allow", Boolean.toString(config.isAllowSms())); //$NON-NLS-1$
		updateBlobConfig("otp.sms.body", config.getSmsBody()); //$NON-NLS-1$
		updateConfig("otp.sms.headers", config.getSmsHeaders()); //$NON-NLS-1$
		updateConfig("otp.sms.method", config.getSmsMethod()); //$NON-NLS-1$
		updateConfig("otp.sms.check", config.getSmsResponseToCheck()); //$NON-NLS-1$
		updateConfig("otp.sms.url", config.getSmsUrl()); //$NON-NLS-1$
		updateConfig("otp.sms.digits", config.getSmsDigits()); //$NON-NLS-1$
		updateConfig("otp.sms.lock", config.getSmsLock()); //$NON-NLS-1$
		
		updateConfig("otp.voice.allow", Boolean.toString(config.isAllowVoice())); //$NON-NLS-1$
		updateBlobConfig("otp.voice.body", config.getVoiceBody()); //$NON-NLS-1$
		updateConfig("otp.voice.headers", config.getVoiceHeaders()); //$NON-NLS-1$
		updateConfig("otp.voice.method", config.getVoiceMethod()); //$NON-NLS-1$
		updateConfig("otp.voice.check", config.getVoiceResponseToCheck()); //$NON-NLS-1$
		updateConfig("otp.voice.url", config.getVoiceUrl()); //$NON-NLS-1$

		updateConfig("otp.hotp.allow", Boolean.toString(config.isAllowHotp())); //$NON-NLS-1$
		updateConfig("otp.hotp.algorithm", config.getHotpAlgorithm()); //$NON-NLS-1$
		updateConfig("otp.hotp.digits", config.getHotpDigits()); //$NON-NLS-1$
		updateConfig("otp.hotp.issuer", config.getHotpIssuer()); //$NON-NLS-1$
		updateConfig("otp.hotp.lock", config.getHotpLock()); //$NON-NLS-1$
		
		updateConfig("otp.totp.allow", Boolean.toString(config.isAllowTotp())); //$NON-NLS-1$
		updateConfig("otp.totp.algorithm", config.getTotpAlgorithm()); //$NON-NLS-1$
		updateConfig("otp.totp.digits", config.getTotpDigits()); //$NON-NLS-1$
		updateConfig("otp.totp.issuer", config.getTotpIssuer()); //$NON-NLS-1$
		updateConfig("otp.totp.lock", config.getTotpLock()); //$NON-NLS-1$
		
		updateConfig("otp.pin.allow", config.isAllowPin()); //$NON-NLS-1$
		updateConfig("otp.pin.digits", config.getPinDigits()); //$NON-NLS-1$
		updateConfig("otp.pin.length", config.getPinLength()); //$NON-NLS-1$
		updateConfig("otp.pin.lock", config.getPinLock()); //$NON-NLS-1$
		
	}
	
	
	protected void updateConfig(String p, Object v) throws InternalErrorException {
		Configuration cfg = getConfigurationService().findParameterByNameAndNetworkName(p, null);
		if (cfg == null && v != null && ! v.toString().trim().isEmpty())  {
			cfg = new Configuration();
			cfg.setCode(p);
			cfg.setValue(v.toString());
			cfg.setDescription(Messages.getString("OtpServiceImpl.130")); //$NON-NLS-1$
			getConfigurationService().create(cfg);
		} else if (cfg != null) {
			if (v == null || v.toString().trim().isEmpty())
				getConfigurationService().delete(cfg);
			else {
				cfg.setValue(v.toString());
				getConfigurationService().update(cfg);
			}
		}
	}

	protected void updateBlobConfig(String p, Object v) throws InternalErrorException {
		Configuration cfg = getConfigurationService().findParameterByNameAndNetworkName(p, null);
		if (cfg != null) {
			getConfigurationService().delete(cfg);
		}
		if (v == null || v.toString().trim().isEmpty())
			getConfigurationService().deleteBlob(p);
		else
			getConfigurationService().updateBlob(p, v.toString().getBytes(StandardCharsets.UTF_8));
	}


	@Override
	protected void handleUpdateDevice(OtpDevice device) throws Exception {
		OtpDeviceEntity entity = getOtpDeviceEntityDao().load(device.getId());
		if (entity != null) {
			if (device.getStatus() == OtpStatus.CREATED &&
					Security.isUserInRole("otp:manage")) { //$NON-NLS-1$
				entity.setStatus(device.getStatus());
				getOtpDeviceEntityDao().update(entity);
			}
			else if (device.getStatus() == OtpStatus.DISABLED &&
					(Security.isUserInRole("otp:manage") || Security.isUserInRole("otp:cancel")))  { //$NON-NLS-1$ //$NON-NLS-2$
				entity.setStatus(device.getStatus());
				getOtpDeviceEntityDao().update(entity);
			}
			else if (device.getStatus() == OtpStatus.VALIDATED &&
					(Security.isUserInRole("otp:manage") || Security.isUserInRole("otp:unlock")))  { //$NON-NLS-1$ //$NON-NLS-2$
				entity.setStatus(device.getStatus());
				getOtpDeviceEntityDao().update(entity);
			}
			else if (device.getStatus() == OtpStatus.LOCKED &&
					(Security.isUserInRole("otp:manage") || Security.isUserInRole("otp:unlock")))  { //$NON-NLS-1$ //$NON-NLS-2$
				entity.setStatus(device.getStatus());
				getOtpDeviceEntityDao().update(entity);
			}
			else
				throw new SecurityException(Messages.getString("OtpServiceImpl.5")); //$NON-NLS-1$
		}
	}

	@Override
	protected void handleDeleteDevice(OtpDevice device) throws Exception {
		OtpDeviceEntity entity = getOtpDeviceEntityDao().load(device.getId());
		if (entity != null) {
			getOtpDeviceEntityDao().remove(entity);
		}
		
	}

	@Override
	protected AsyncList<OtpDevice> handleFindOtpDevicesByJsonQueryAsync(String text, String query) throws Exception {
		final AsyncList<OtpDevice> result = new AsyncList<OtpDevice>();
		getAsyncRunnerService().run(new Runnable() {
			@Override
			public void run() {
				try {
					doFindOtpDevicesByJsonQuery(text, query, null, null, result);
				} catch (Throwable e) {
					throw new RuntimeException(e);
				}				
			}
		}, result);

		return result;
	}

	@Override
	protected PagedResult<OtpDevice> handleFindOtpDevicesByJsonQuery(String text, String query, Integer firstResult ,
			Integer pageSize) throws Exception {
		final LinkedList<OtpDevice> result = new LinkedList<OtpDevice>();
		return doFindOtpDevicesByJsonQuery(text, query, firstResult, pageSize, result);
	}

	protected PagedResult<OtpDevice> doFindOtpDevicesByJsonQuery(String text, String query, Integer firstResult ,
			Integer pageSize, List<OtpDevice> result) throws Exception {
		ScimHelper h = new ScimHelper(OtpDevice.class);
		h.setPrimaryAttributes(new String[] { "user", "name"}); //$NON-NLS-1$ //$NON-NLS-2$
		CriteriaSearchConfiguration config = new CriteriaSearchConfiguration();
		config.setFirstResult(firstResult);
		config.setMaximumResultSize(pageSize);
		h.setConfig(config);
		h.setTenantFilter("tenant.id"); //$NON-NLS-1$
		
		OtpDeviceEntityDao dao = getOtpDeviceEntityDao();

		h.setGenerator((entity) -> {
			OtpDeviceEntity ne = (OtpDeviceEntity) entity;
				return dao.toOtpDevice((OtpDeviceEntity) entity);
		}); 
		h.search(text, query, (Collection) result ); 
		PagedResult<OtpDevice> pr = new PagedResult<>();
		pr.setStartIndex(firstResult == null ? 0: firstResult);
		pr.setItemsPerPage(pageSize);
		pr.setTotalResults(h.count());
		pr.setResources(result);
		return pr;
	}

	@Override
	protected boolean handleValidateChalleng(OtpDevice device, String pin) throws Exception {
		OtpDeviceEntity entity = getOtpDeviceEntityDao().load(device.getId());
		boolean valid = false;
		if (entity.getType() == OtpDeviceType.EMAIL) {
			valid = getEmailValidationService().validatePin(entity, handleGetConfiguration(), pin);
		}
		if (entity.getType() == OtpDeviceType.SMS) {
			valid = getSmsValidationService().validatePin(entity, handleGetConfiguration(), pin);
		}
		if (entity.getType() == OtpDeviceType.HOTP) {
			valid = getHotpValidationService().validatePin(entity, handleGetConfiguration(), pin);
		}
		if (entity.getType() == OtpDeviceType.TOTP) {
			valid = getTotpValidationService().validatePin(entity, handleGetConfiguration(), pin);
		}
		if (entity.getType() == OtpDeviceType.PIN) {
			valid = getPinValidationService().validatePin(entity, handleGetConfiguration(), pin);
		}
		return valid;
	}

	@Override
	protected Challenge handleGenerateChallenge(OtpDevice device) throws Exception {
		OtpDeviceEntity entity = getOtpDeviceEntityDao().load(device.getId());
		final OtpConfig cfg = handleGetConfiguration();
		Challenge challenge = new Challenge();
		challenge.setCardNumber(entity.getName());
		challenge.setCell("PIN"); //$NON-NLS-1$
		if (device.getType() == OtpDeviceType.EMAIL) {
			getEmailValidationService().sendPin(entity, cfg);
		}
		if (device.getType() == OtpDeviceType.SMS) {
			getSmsValidationService().sendPin(entity, cfg);
		}
		if (device.getType() == OtpDeviceType.PIN) {
			String pattern = getPinValidationService().selectDigits(entity, cfg);
			if (pattern != null)
				challenge.setCell(Messages.getString("OtpServiceImpl.6")+pattern); //$NON-NLS-1$
		}
		return challenge;
	}
}

