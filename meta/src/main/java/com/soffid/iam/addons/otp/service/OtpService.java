//
// (C) 2013 Soffid
// 
// This file is licensed by Soffid under GPL v3 license
//

package com.soffid.iam.addons.otp.service;
import java.util.List;

import org.springframework.transaction.annotation.Transactional;

import com.soffid.iam.addons.otp.common.OtpConfig;
import com.soffid.iam.addons.otp.common.OtpDevice;
import com.soffid.iam.addons.otp.model.OtpDeviceEntity;
import com.soffid.iam.addons.otp.roles.otp_cancel;
import com.soffid.iam.addons.otp.roles.otp_manage;
import com.soffid.iam.addons.otp.roles.otp_query;
import com.soffid.iam.addons.otp.roles.otp_unlock;
import com.soffid.iam.addons.otp.service.impl.EmailValidationService;
import com.soffid.iam.addons.otp.service.impl.HotpValidationService;
import com.soffid.iam.addons.otp.service.impl.PinValidationService;
import com.soffid.iam.addons.otp.service.impl.SmsValidationService;
import com.soffid.iam.addons.otp.service.impl.TotpValidationService;
import com.soffid.iam.api.AsyncList;
import com.soffid.iam.api.PagedResult;
import com.soffid.iam.service.AsyncRunnerService;
import com.soffid.mda.annotation.Depends;
import com.soffid.mda.annotation.Description;
import com.soffid.mda.annotation.Nullable;
import com.soffid.mda.annotation.Operation;
import com.soffid.mda.annotation.Service;

import es.caib.seycon.ng.comu.Challenge;
import es.caib.seycon.ng.model.ConfiguracioEntity;
import es.caib.seycon.ng.model.MaquinaEntity;
import es.caib.seycon.ng.servei.ConfiguracioService;
import es.caib.seycon.ng.servei.XarxaService;

@Service(serverRole = "agent", serverPath = "/seycon/otpService")
@Depends ({
	MaquinaEntity.class,
	OtpDeviceEntity.class,
	XarxaService.class,
	TotpValidationService.class,
	HotpValidationService.class,
	SmsValidationService.class,
	EmailValidationService.class,
	PinValidationService.class,
	es.caib.seycon.ng.model.UsuariEntity.class,
	ConfiguracioService.class,
	ConfiguracioEntity.class, 
	AsyncRunnerService.class})
public abstract class OtpService {
	@Operation ( grantees={otp_manage.class})
	@Transactional(rollbackFor={java.lang.Exception.class})
	public OtpDevice registerDevice(String user, OtpDevice device) { return null;}

	@Operation ( grantees={otp_manage.class})
	@Description("Method to register a device from a sync-server agent")
	@Transactional(rollbackFor={java.lang.Exception.class})
	public OtpDevice registerDevice2(String user, OtpDevice device) { return null;}

	@Operation ( grantees={otp_manage.class})
	@Transactional(rollbackFor={java.lang.Exception.class})
	public OtpDevice importDevice(String user, OtpDevice device, @Nullable String secret) { return null;}

	@Operation ( grantees={otp_cancel.class})
	@Transactional(rollbackFor={java.lang.Exception.class})
	public void cancelDevice(OtpDevice device) { return ;}

	@Operation ( grantees={otp_unlock.class})
	@Transactional(rollbackFor={java.lang.Exception.class})
	public void unlockDevice(OtpDevice device) { return ;}

	@Operation ( grantees={otp_query.class})
	@Transactional(rollbackFor={java.lang.Exception.class})
	public List<OtpDevice> findUserDevices(String users) { return null;}

	@Operation ( grantees={otp_manage.class, otp_unlock.class, otp_cancel.class})
	public void updateDevice(OtpDevice device)
		throws es.caib.seycon.ng.exception.InternalErrorException {
	}

	@Operation ( grantees={otp_manage.class, otp_unlock.class, otp_cancel.class})
	public Challenge generateChallenge(OtpDevice device)
		throws es.caib.seycon.ng.exception.InternalErrorException {
		return null;
	}

	@Operation ( grantees={otp_manage.class, otp_unlock.class, otp_cancel.class})
	public boolean validateChalleng(OtpDevice device, String pin)
		throws es.caib.seycon.ng.exception.InternalErrorException {
		return false;
	}

	@Operation ( grantees={otp_manage.class})
	public void deleteDevice(OtpDevice device)
		throws es.caib.seycon.ng.exception.InternalErrorException {
	}

	@Operation ( grantees={otp_manage.class})
	public void update(
		OtpConfig config)
		throws es.caib.seycon.ng.exception.InternalErrorException {
	}
	
	@Operation ( grantees={otp_manage.class})
	@Transactional(rollbackFor={java.lang.Exception.class})
	public OtpConfig getConfiguration()
		throws es.caib.seycon.ng.exception.InternalErrorException {
	 return null;
	}
	
	@Operation ( grantees={otp_manage.class})
	public AsyncList<OtpDevice> findOtpDevicesByJsonQueryAsync (@Nullable String text, @Nullable String query) { return null;}

	@Operation ( grantees={otp_manage.class})
	public PagedResult<OtpDevice> findOtpDevicesByJsonQuery (@Nullable String text,@Nullable String query, @Nullable Integer firstResult, @Nullable Integer pageSize) {return null;}
}
