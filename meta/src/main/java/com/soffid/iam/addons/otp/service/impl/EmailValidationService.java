package com.soffid.iam.addons.otp.service.impl;

import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import com.soffid.iam.addons.otp.common.OtpConfig;
import com.soffid.iam.addons.otp.common.OtpDevice;
import com.soffid.iam.addons.otp.model.OtpDeviceEntity;
import com.soffid.iam.service.AsyncRunnerService;
import com.soffid.iam.service.MailService;
import com.soffid.mda.annotation.Depends;
import com.soffid.mda.annotation.Service;

import es.caib.seycon.ng.model.DadaUsuariEntity;
import es.caib.seycon.ng.model.UsuariEntity;

@Service(internal = true)
@Depends({OtpDeviceEntity.class, MailService.class, DadaUsuariEntity.class, UsuariEntity.class,
	AsyncRunnerService.class})
public class EmailValidationService {
	void sendPin(OtpDeviceEntity device, OtpConfig cfg) {}
	boolean validatePin (OtpDeviceEntity challenge, OtpConfig cfg, String pin) {return false;}
}
