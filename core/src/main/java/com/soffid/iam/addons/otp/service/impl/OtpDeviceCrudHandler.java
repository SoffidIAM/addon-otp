package com.soffid.iam.addons.otp.service.impl;

import java.util.Date;

import javax.naming.InitialContext;
import javax.naming.NamingException;

import com.soffid.iam.addons.otp.common.OtpDevice;
import com.soffid.iam.addons.otp.service.ejb.OtpService;
import com.soffid.iam.addons.otp.service.ejb.OtpServiceHome;
import com.soffid.iam.api.AsyncList;
import com.soffid.iam.api.CrudHandler;
import com.soffid.iam.api.PagedResult;
import com.soffid.iam.utils.Security;

public class OtpDeviceCrudHandler implements CrudHandler<OtpDevice> {
	OtpService svc;
	
	public OtpDeviceCrudHandler() throws NamingException {
		svc = (OtpService) new InitialContext().lookup(OtpServiceHome.JNDI_NAME);
	}
	
	public OtpDevice create(OtpDevice object) throws Exception {
		object.setCreated(new Date());
		return svc.registerDevice(object.getUser(), object);
	}

	public PagedResult<OtpDevice> read(String text, String filter, Integer start, Integer maxobjects) throws Exception {
		return svc.findOtpDevicesByJsonQuery(text, filter, start, maxobjects);
	}

	public AsyncList<OtpDevice> readAsync(String text, String filter) throws Exception {
		return svc.findOtpDevicesByJsonQueryAsync(text, filter);
	}

	public OtpDevice update(OtpDevice object) throws Exception {
		svc.updateDevice(object);
		return object;
	}

	public void delete(OtpDevice object) throws Exception {
		svc.deleteDevice(object);
	}

}
