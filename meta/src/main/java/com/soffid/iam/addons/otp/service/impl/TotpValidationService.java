package com.soffid.iam.addons.otp.service.impl;

import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import com.soffid.iam.addons.otp.common.OtpConfig;
import com.soffid.iam.addons.otp.common.OtpDevice;
import com.soffid.iam.addons.otp.model.OtpDeviceEntity;
import com.soffid.iam.service.AsyncRunnerService;
import com.soffid.mda.annotation.Depends;
import com.soffid.mda.annotation.Service;

import es.caib.seycon.ng.comu.Challenge;

@Service(internal = true)
@Depends({OtpDeviceEntity.class,
	AsyncRunnerService.class})
public class TotpValidationService {
	boolean validatePin (OtpDeviceEntity challenge, OtpConfig cfg, String pin) {return false;}
	byte[] generateKey(OtpDeviceEntity entity, OtpConfig cfg) {return null;}
}
