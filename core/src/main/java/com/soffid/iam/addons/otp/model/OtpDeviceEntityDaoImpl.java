package com.soffid.iam.addons.otp.model;

import com.soffid.iam.addons.otp.common.OtpDevice;

public class OtpDeviceEntityDaoImpl extends OtpDeviceEntityDaoBase {

	@Override
	public void toOtpDevice(OtpDeviceEntity source, OtpDevice target) {
		super.toOtpDevice(source, target);
		target.setUser(source.getUser().getUserName());
	}

}
