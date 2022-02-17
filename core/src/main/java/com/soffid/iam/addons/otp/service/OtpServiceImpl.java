package com.soffid.iam.addons.otp.service;

import java.awt.image.BufferedImage;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
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
			throw new InternalErrorException("Wrong user "+user);
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
				throw new InternalErrorException("Email address cannot be empty");
			char[] ach = device.getEmail().toCharArray();
			int step = 0;
			for (int i = 0; i < ach.length; i++)
			{
				if (ach[i] == '.' || ach[i] == '@') step = 0;
				else if (step ++ >= 2) ach[i] = '*';
			}
			entity.setEmail(device.getEmail());
			entity.setName("Email message to "+new String(ach));
		}
		if (device.getType() == OtpDeviceType.SMS) {
			if (device.getPhone() == null || device.getPhone().trim().isEmpty())
				throw new InternalErrorException("Phone number cannot be empty");
			char[] ach = device.getPhone().toCharArray();
			int step = 0;
			for (int i = 2; i < ach.length - 2; i++)
			{
				ach[i] = '*';
			}
			entity.setPhone(device.getPhone());
			entity.setName("SMS message to "+new String(ach));
		}
		if (device.getType() == OtpDeviceType.TOTP) {
			String last = getTokenId("TOTP");
			entity.setName(last);
			byte[] key = getTotpValidationService().generateKey(entity, handleGetConfiguration() );
			image = generateTotpQR(entity, key);
		}
		if (device.getType() == OtpDeviceType.HOTP) {
			String last = getTokenId("HOTP");
			entity.setName(last);
			byte[] key = getHotpValidationService().generateKey(entity, handleGetConfiguration());
			image = generateHotpQR(entity, key);
		}
		if (device.getType() == OtpDeviceType.PIN) {
			OtpConfig cfg = handleGetConfiguration();
			if (device.getPin().getPassword().length() < cfg.getPinLength())
				throw new InternalErrorException(String.format("The security number must contain at least %d numbers", cfg.getPinLength()));
			entity.setName("Security number");
			entity.setPin(device.getPin().toString());
		}
		getOtpDeviceEntityDao().create(entity);
		device = getOtpDeviceEntityDao().toOtpDevice(entity);
		device.setImage(image);
		return device;
	}

	private BufferedImage generateTotpQR(OtpDeviceEntity entity, byte[] key) throws Exception {
		OtpConfig cfg = handleGetConfiguration();
		String url = "otpauth://totp/"+
				URLEncoder.encode(cfg.getTotpIssuer(),"UTF-8")+
				":"+entity.getName()+" "+ 
				URLEncoder.encode(entity.getUser().getFullName().replace(' ', '_'), "UTF-8");
		url += "?secret="+encodeKey(key);
		url += "&issuer="+ URLEncoder.encode(cfg.getTotpIssuer(), "UTF-8");
		url += "&algorithm="+URLEncoder.encode(entity.getAlgorithm().substring(4), "UTF-8");
		url += "&digits="+URLEncoder.encode(entity.getDigits().toString(), "UTF-8") ;
		url += "&period=30";
		url += "&image="+URLEncoder.encode("https://www.soffid.com/favicon-150.png", "UTF-8");
		
		QRCodeWriter barcodeWriter = new QRCodeWriter();
	    BitMatrix bitMatrix = 
	    	      barcodeWriter.encode(url, BarcodeFormat.QR_CODE, 200, 200);

   	    BufferedImage img = MatrixToImageWriter.toBufferedImage(bitMatrix);
   	    
   	    return img;
	}

	private BufferedImage generateHotpQR(OtpDeviceEntity entity, byte[] key) throws Exception {
		OtpConfig cfg = handleGetConfiguration();
		String url = "otpauth://hotp/"+
				URLEncoder.encode(cfg.getHotpIssuer(),"UTF-8")+
				":"+entity.getName()+" "+ 
				URLEncoder.encode(entity.getUser().getFullName().replace(' ', '_'), "UTF-8");
		url += "?secret="+encodeKey(key);
		url += "&issuer="+ URLEncoder.encode(cfg.getHotpIssuer(), "UTF-8");
		url += "&algorithm="+URLEncoder.encode(entity.getAlgorithm().substring(4), "UTF-8");
		url += "&digits="+URLEncoder.encode(entity.getDigits().toString(), "UTF-8") ;
		url += "&counter=0";
		url += "&image="+URLEncoder.encode("https://www.soffid.com/favicon-150.png", "UTF-8");
		
		QRCodeWriter barcodeWriter = new QRCodeWriter();
	    BitMatrix bitMatrix = 
	    	      barcodeWriter.encode(url, BarcodeFormat.QR_CODE, 200, 200);

   	    BufferedImage img = MatrixToImageWriter.toBufferedImage(bitMatrix);
   	    
   	    return img;
	}

	protected String encodeKey(byte[] key) throws UnsupportedEncodingException {
		String s = new Base32().encodeAsString(key);
		while (s.endsWith("="))
			s = s.substring(0, s.length()-1);
		return s;
	}

	protected String getTokenId(String prefix) {
		ConfigEntity cfg = getConfigEntityDao().findByCodeAndNetworkCode("addon.otp.next-token", null);
		if (cfg == null)
		{
			cfg = getConfigEntityDao().newConfigEntity();
			cfg.setDescription("Next OTP Token");
			cfg.setName("addon.otp.next-token");
			cfg.setValue("1");
		}
		String last = cfg.getValue();
		String next = Integer.toString(Integer.parseInt(last)+1);
		while (last.length() < 8) last = "0"+last;
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

		configuration.setAllowEmail( "true".equals(getConfigDefault("otp.email.allow", "false")));
		configuration.setEmailBody( getConfigDefault("otp.email.body", "Your authentication code is ${PIN}"));
		configuration.setEmailSubject( getConfigDefault("otp.email.subject", "Authentication code"));
		configuration.setEmailDigits(Integer.decode( getConfigDefault("otp.email.digits", "6")));
		
		configuration.setAllowSms("true".equals(getConfigDefault("otp.sms.allow", "false")));
		configuration.setSmsBody( getConfigDefault("otp.sms.body", ""));
		configuration.setSmsHeaders( getConfigDefault("otp.sms.headers", ""));
		configuration.setSmsMethod( getConfigDefault("otp.sms.method", "GET"));
		configuration.setSmsResponseToCheck( getConfigDefault("otp.sms.check", ""));
		configuration.setSmsUrl( getConfigDefault("otp.sms.url", "https://www.ovh.com/cgi-bin/sms/http2sms.cgi?account=...&password=...&login=...&from=...&"
				+ "to=${PHONE}&"
				+ "message=Your authentication code is: ${PIN}&"
				+ "noStop&contentType=application/json&class=0"));
		configuration.setSmsDigits(Integer.decode( getConfigDefault("otp.sms.digits", "6")));

		configuration.setAllowHotp("true".equals(getConfigDefault("otp.hotp.allow", "false")));
		configuration.setHotpAlgorithm(getConfigDefault("otp.hotp.algorithm", "HmacSHA1"));
		configuration.setHotpDigits(Integer.decode( getConfigDefault("otp.hotp.digits", "6")));
		configuration.setHotpIssuer(getConfigDefault("otp.hotp.issuer", "Issuer"));

		configuration.setAllowTotp("true".equals(getConfigDefault("otp.totp.allow", "false")));
		configuration.setTotpAlgorithm(getConfigDefault("otp.totp.algorithm", "HmacSHA1"));
		configuration.setTotpDigits(Integer.decode( getConfigDefault("otp.totp.digits", "6")));
		configuration.setTotpIssuer(getConfigDefault("otp.totp.issuer", "Issuer"));
		
		configuration.setAllowPin("true".equals(getConfigDefault("otp.pin.allow", "false")));
		configuration.setPinDigits( Integer.parseInt( getConfigDefault("otp.pin.digits", "3")) );
		configuration.setPinLength( Integer.parseInt( getConfigDefault("otp.pin.length", "8")));

		return configuration;
	}

	protected String getConfigDefault(String p, String def) {
		String v = ConfigurationCache.getProperty(p);
		return v != null ? v: def;
	}

	@Override
	protected void handleUpdate(OtpConfig config) throws Exception {
		updateConfig("otp.email.allow", Boolean.toString(config.isAllowEmail()));
		updateConfig("otp.email.body", config.getEmailBody());
		updateConfig("otp.email.subject", config.getEmailSubject());
		updateConfig("otp.email.digits", config.getEmailDigits());
		
		updateConfig("otp.sms.allow", Boolean.toString(config.isAllowSms()));
		updateConfig("otp.sms.body", config.getSmsBody());
		updateConfig("otp.sms.headers", config.getSmsHeaders());
		updateConfig("otp.sms.method", config.getSmsMethod());
		updateConfig("otp.sms.check", config.getSmsResponseToCheck());
		updateConfig("otp.sms.url", config.getSmsUrl());
		updateConfig("otp.sms.digits", config.getSmsDigits());
		
		updateConfig("otp.hotp.allow", Boolean.toString(config.isAllowHotp()));
		updateConfig("otp.hotp.algorithm", config.getHotpAlgorithm());
		updateConfig("otp.hotp.digits", config.getHotpDigits());
		updateConfig("otp.hotp.issuer", config.getHotpIssuer());
		
		updateConfig("otp.totp.allow", Boolean.toString(config.isAllowTotp()));
		updateConfig("otp.totp.algorithm", config.getTotpAlgorithm());
		updateConfig("otp.totp.digits", config.getTotpDigits());
		updateConfig("otp.totp.issuer", config.getTotpIssuer());
		
		updateConfig("otp.pin.allow", config.isAllowPin());
		updateConfig("otp.pin.digits", config.getPinDigits());
		updateConfig("otp.pin.length", config.getPinLength());
		
	}
	
	
	protected void updateConfig(String p, Object v) throws InternalErrorException {
		Configuration cfg = getConfigurationService().findParameterByNameAndNetworkName(p, null);
		if (cfg == null && v != null && ! v.toString().trim().isEmpty())  {
			cfg = new Configuration();
			cfg.setCode(p);
			cfg.setValue(v.toString());
			cfg.setDescription("Auto generated value");
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

	@Override
	protected void handleUpdateDevice(OtpDevice device) throws Exception {
		OtpDeviceEntity entity = getOtpDeviceEntityDao().load(device.getId());
		if (entity != null) {
			if (device.getStatus() == OtpStatus.CREATED &&
					Security.isUserInRole("otp:manage")) {
				entity.setStatus(device.getStatus());
				getOtpDeviceEntityDao().update(entity);
			}
			else if (device.getStatus() == OtpStatus.DISABLED &&
					(Security.isUserInRole("otp:manage") || Security.isUserInRole("otp:cancel")))  {
				entity.setStatus(device.getStatus());
				getOtpDeviceEntityDao().update(entity);
			}
			else if (device.getStatus() == OtpStatus.VALIDATED &&
					(Security.isUserInRole("otp:manage") || Security.isUserInRole("otp:unlock")))  {
				entity.setStatus(device.getStatus());
				getOtpDeviceEntityDao().update(entity);
			}
			else if (device.getStatus() == OtpStatus.LOCKED &&
					(Security.isUserInRole("otp:manage") || Security.isUserInRole("otp:unlock")))  {
				entity.setStatus(device.getStatus());
				getOtpDeviceEntityDao().update(entity);
			}
			else
				throw new SecurityException("Not authorized");
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
		h.setPrimaryAttributes(new String[] { "user", "name"});
		CriteriaSearchConfiguration config = new CriteriaSearchConfiguration();
		config.setFirstResult(firstResult);
		config.setMaximumResultSize(pageSize);
		h.setConfig(config);
		h.setTenantFilter("tenant.id");
		
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
		challenge.setCell("PIN");
		if (device.getType() == OtpDeviceType.EMAIL) {
			getEmailValidationService().sendPin(entity, cfg);
		}
		if (device.getType() == OtpDeviceType.SMS) {
			getSmsValidationService().sendPin(entity, cfg);
		}
		if (device.getType() == OtpDeviceType.PIN) {
			String pattern = getPinValidationService().selectDigits(entity, cfg);
			if (pattern != null)
				challenge.setCell("digits "+pattern);
		}
		return challenge;
	}
}

