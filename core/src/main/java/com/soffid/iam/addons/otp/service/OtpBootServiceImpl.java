package com.soffid.iam.addons.otp.service;

import com.soffid.iam.addons.otp.service.impl.InternalOTPHandler;
import com.soffid.iam.api.Tenant;
import com.soffid.iam.sync.SoffidApplication;
import com.soffid.iam.sync.jetty.JettyServer;

public class OtpBootServiceImpl extends OtpBootServiceBase {

	@Override
	protected void handleConsoleBoot() throws Exception {
		final InternalOTPHandler handler = new InternalOTPHandler();
		handler.setHotpValidationService( getHotpValidationService());
		handler.setTotpValidationService( getTotpValidationService());
		handler.setEmailValidationService( getEmailValidationService());
		handler.setSmsValidationService( getSmsValidationService());
		handler.setOtpDeviceEntityDao( getOtpDeviceEntityDao());
		handler.setOtpService(getOtpService());
		getOTPValidationService().registerOTPHandler(handler);
	}

	@Override
	protected void handleSyncServerBoot() throws Exception {
	}

	@Override
	protected void handleTenantBoot(Tenant arg0) throws Exception {
	}

}
