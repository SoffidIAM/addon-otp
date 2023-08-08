package com.soffid.iam.addons.otp.service.impl;

import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import com.soffid.iam.addons.otp.common.OtpConfig;
import com.soffid.iam.addons.otp.common.OtpDevice;
import com.soffid.iam.addons.otp.model.OtpDeviceEntity;
import com.soffid.iam.service.AsyncRunnerService;
import com.soffid.mda.annotation.Depends;
import com.soffid.mda.annotation.Description;
import com.soffid.mda.annotation.Service;

import es.caib.seycon.ng.model.DadaUsuariEntity;
import es.caib.seycon.ng.model.UsuariEntity;

@Service(internal = true)
@Depends({OtpDeviceEntity.class,
	DadaUsuariEntity.class,
	UsuariEntity.class,
	AsyncRunnerService.class})
public class PinValidationService {
	@Description("Returns the digits to enter")
	String selectDigits(OtpDeviceEntity device, OtpConfig cfg) {return null;}
	boolean validatePin (OtpDeviceEntity challenge, OtpConfig cfg, String pin) {return false;}
}
