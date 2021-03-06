package com.soffid.iam.addons.otp.service;

import com.soffid.iam.addons.otp.common.OtpDevice;
import com.soffid.iam.addons.otp.service.impl.InternalOTPHandler;
import com.soffid.iam.addons.otp.service.impl.OtpDeviceCrudHandler;
import com.soffid.iam.api.Tenant;

public class OtpBootServiceImpl extends OtpBootServiceBase {

	@Override
	protected void handleConsoleBoot() throws Exception {
		final InternalOTPHandler handler = new InternalOTPHandler();
		handler.setHotpValidationService( getHotpValidationService());
		handler.setTotpValidationService( getTotpValidationService());
		handler.setEmailValidationService( getEmailValidationService());
		handler.setSmsValidationService( getSmsValidationService());
		handler.setOtpDeviceEntityDao( getOtpDeviceEntityDao());
		handler.setPinValidationService(getPinValidationService());
		handler.setOtpService(getOtpService());
		getOTPValidationService().registerOTPHandler(handler);
		
		getCrudRegistryService().registerHandler(OtpDevice.class, new OtpDeviceCrudHandler());
	}

	@Override
	protected void handleSyncServerBoot() throws Exception {
		final InternalOTPHandler handler = new InternalOTPHandler();
		handler.setHotpValidationService( getHotpValidationService());
		handler.setTotpValidationService( getTotpValidationService());
		handler.setEmailValidationService( getEmailValidationService());
		handler.setSmsValidationService( getSmsValidationService());
		handler.setPinValidationService(getPinValidationService());
		handler.setOtpDeviceEntityDao( getOtpDeviceEntityDao());
		handler.setOtpService(getOtpService());
		getOTPValidationService().registerOTPHandler(handler);
//		getCrudRegistryService().registerHandler(OtpDevice.class, new OtpDeviceCrudHandler());
	}

	@Override
	protected void handleTenantBoot(Tenant arg0) throws Exception {
	}

}
