package com.soffid.iam.addons.otp.service;

import com.soffid.iam.addons.otp.model.OtpDeviceEntity;
import com.soffid.iam.addons.otp.service.impl.EmailValidationService;
import com.soffid.iam.addons.otp.service.impl.HotpValidationService;
import com.soffid.iam.addons.otp.service.impl.PinValidationService;
import com.soffid.iam.addons.otp.service.impl.SmsValidationService;
import com.soffid.iam.addons.otp.service.impl.TotpValidationService;
import com.soffid.iam.service.OTPValidationService;
import com.soffid.mda.annotation.Depends;
import com.soffid.mda.annotation.Service;

import es.caib.seycon.ng.servei.ApplicationBootService;

@Service(internal=true)
@Depends({
	OtpService.class,
	OtpDeviceEntity.class,
	EmailValidationService.class,
	HotpValidationService.class,
	TotpValidationService.class,
	SmsValidationService.class,
	OTPValidationService.class,
	PinValidationService.class})
public class OtpBootService extends ApplicationBootService {

}
