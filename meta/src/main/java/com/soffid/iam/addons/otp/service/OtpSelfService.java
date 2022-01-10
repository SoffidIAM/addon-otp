//
// (C) 2013 Soffid
// 
// This file is licensed by Soffid under GPL v3 license
//

package com.soffid.iam.addons.otp.service;
import com.soffid.iam.addons.otp.common.OtpDevice;
import com.soffid.iam.addons.otp.common.OtpDeviceType;
import com.soffid.iam.addons.otp.model.OtpDeviceEntity;
import com.soffid.iam.addons.otp.roles.otp_manage;
import com.soffid.iam.addons.otp.roles.otp_user;
import com.soffid.iam.addons.otp.roles.tothom;
import com.soffid.iam.addons.otp.service.impl.EmailValidationService;
import com.soffid.iam.addons.otp.service.impl.HotpValidationService;
import com.soffid.iam.addons.otp.service.impl.PinValidationService;
import com.soffid.iam.addons.otp.service.impl.SmsValidationService;
import com.soffid.iam.addons.otp.service.impl.TotpValidationService;
import com.soffid.mda.annotation.*;

import java.util.List;

import org.springframework.transaction.annotation.Transactional;

@Depends ({es.caib.seycon.ng.servei.ConfiguracioService.class,
	OtpDeviceEntity.class,
	OtpService.class,
	es.caib.seycon.ng.model.UsuariEntity.class,
	EmailValidationService.class,
	HotpValidationService.class,
	TotpValidationService.class,
	PinValidationService.class,
	SmsValidationService.class})
@Service ( grantees = {otp_user.class})
public abstract class OtpSelfService {
	@Operation ( grantees={otp_manage.class})
	@Transactional(rollbackFor={java.lang.Exception.class})
	public OtpDevice registerDevice(OtpDevice device) { return null;}

	@Operation ( grantees={otp_manage.class})
	@Transactional(rollbackFor={java.lang.Exception.class})
	public boolean enableDevice(OtpDevice device, String pin) { return false;}

	@Operation ( grantees={otp_manage.class})
	@Transactional(rollbackFor={java.lang.Exception.class})
	public void cancelDevice(OtpDevice device) { return ;}

	@Operation ( grantees={tothom.class})
	@Transactional(rollbackFor={java.lang.Exception.class})
	public List<OtpDevice> findMyDevices() { return null;}
	
	@Operation ( grantees={tothom.class})
	public List<OtpDeviceType> findEnabledDeviceTypes() { return null;}
	

}
