package com.soffid.iam.addons.otp.service;

import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;

import com.soffid.iam.addons.otp.common.OtpConfig;
import com.soffid.iam.addons.otp.common.OtpDevice;
import com.soffid.iam.addons.otp.common.OtpDeviceType;
import com.soffid.iam.addons.otp.common.OtpStatus;
import com.soffid.iam.addons.otp.model.OtpDeviceEntity;
import com.soffid.iam.api.Password;
import com.soffid.iam.utils.Security;

import es.caib.seycon.ng.exception.InternalErrorException;

public class OtpSelfServiceImpl extends OtpSelfServiceBase {

	@Override
	protected boolean handleEnableDevice(OtpDevice device, String pin) throws Exception {
		OtpDeviceEntity entity = getOtpDeviceEntityDao().load(device.getId());
		if (entity == null)
			throw new InternalErrorException("Unable to find device "+device.getId());
		if (entity.getStatus() == OtpStatus.VALIDATED)
			return true;
		if (entity.getStatus() != OtpStatus.CREATED)
			return false;
		boolean valid = false;
		if (entity.getType() == OtpDeviceType.EMAIL) {
			valid = getEmailValidationService().validatePin(entity, getOtpService().getConfiguration(), pin);
		}
		if (entity.getType() == OtpDeviceType.SMS) {
			valid = getSmsValidationService().validatePin(entity, getOtpService().getConfiguration(), pin);
		}
		if (entity.getType() == OtpDeviceType.HOTP) {
			valid = getHotpValidationService().validatePin(entity, getOtpService().getConfiguration(), pin);
		}
		if (entity.getType() == OtpDeviceType.TOTP) {
			valid = getTotpValidationService().validatePin(entity, getOtpService().getConfiguration(), pin);
		}
		if (entity.getType() == OtpDeviceType.PIN) {
			valid = getPinValidationService().validatePin(entity, getOtpService().getConfiguration(), pin);
		}
		return valid;
	}

	@Override
	protected OtpDevice handleRegisterDevice(OtpDevice device) throws Exception {
		Password pin = device.getPin();
		device = getOtpService().registerDevice(Security.getCurrentUser(), device);
		OtpDeviceEntity entity = getOtpDeviceEntityDao().load(device.getId());
		entity.setStatus(OtpStatus.CREATED);
		getOtpDeviceEntityDao().update(entity);
		final OtpConfig cfg = getOtpService().getConfiguration();
		if (device.getType() == OtpDeviceType.EMAIL) {
			getEmailValidationService().sendPin(entity, cfg);
		}
		if (device.getType() == OtpDeviceType.SMS) {
			getSmsValidationService().sendPin(entity, cfg);
		}
		if (device.getType() == OtpDeviceType.PIN) {
			OtpConfig cfg2 = new OtpConfig(cfg);
			cfg2.setPinDigits(pin.getPassword().length());
			getPinValidationService().selectDigits(entity, cfg2);
		}
		return device;
		
	}

	@Override
	protected List<OtpDevice> handleFindMyDevices() throws Exception {
		List<OtpDeviceEntity> l = getOtpDeviceEntityDao().findByUser(Security.getCurrentUser());
		for (Iterator<OtpDeviceEntity> it = l.iterator(); it.hasNext();) {
			OtpDeviceEntity e = it.next();
			if (e.getStatus() == OtpStatus.DISABLED)
				it.remove();
		}
		return getOtpDeviceEntityDao().toOtpDeviceList(l);
	}

	@Override
	protected void handleCancelDevice(OtpDevice device) throws Exception {
		OtpDeviceEntity entity = getOtpDeviceEntityDao().load(device.getId());
		if (entity == null)
			throw new InternalErrorException("Unable to find device "+device.getId());
		entity.setStatus(OtpStatus.DISABLED);
		getOtpDeviceEntityDao().update(entity);
	}

	@Override
	protected List<OtpDeviceType> handleFindEnabledDeviceTypes() throws Exception {
		List<OtpDeviceType> l = new LinkedList<OtpDeviceType>();
		OtpConfig cfg = getOtpService().getConfiguration();
		if (cfg.isAllowEmail()) l.add (OtpDeviceType.EMAIL);
		if (cfg.isAllowSms()) l.add (OtpDeviceType.SMS);
		if (cfg.isAllowHotp()) l.add (OtpDeviceType.HOTP);
		if (cfg.isAllowTotp()) l.add (OtpDeviceType.TOTP);
		if (cfg.isAllowPin()) l.add (OtpDeviceType.PIN);
		return l;
	}

}
