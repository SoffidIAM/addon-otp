//
// (C) 2013 Soffid
// 
// This file is licensed by Soffid under GPL v3 license
//

package com.soffid.iam.addons.otp.common;
import java.awt.image.BufferedImage;

import com.soffid.iam.addons.otp.model.OtpDeviceEntity;
import com.soffid.iam.model.TenantEntity;
import com.soffid.mda.annotation.*;

import es.caib.seycon.ng.comu.Password;
import es.caib.seycon.ng.model.MaquinaEntity;
import es.caib.seycon.ng.model.UsuariEntity;

@ValueObject 
@JsonObject(hibernateClass = OtpDeviceEntity.class)
public class OtpDevice {

	@Nullable
	public java.lang.Long id;

	@Nullable
	public java.lang.String name;
	
	public OtpDeviceType type;

	@Nullable
	@JsonAttribute(hibernateAttribute = "user.userName")
	public String user;
	
	public java.util.Date created;

	@Nullable
	public java.util.Date lastSeen;

	@Nullable
	public java.util.Date lastUsed;

	int fails;

	@Attribute(defaultValue = "OtpStatus.CREATED")
	OtpStatus status ;

	@Description("Target Email")
	@Nullable
	String email;

	@Description("Target mobile phone")
	@Nullable
	String phone;

	@Description("Security PIN")
	@Nullable
	Password pin;

	@Description("QR Code to configure the OTP client device. Only present on creation")
	@Nullable
	BufferedImage image;

	@Description("QR Code to configure the OTP client device. Only present on creation from sync server")
	@Nullable
	String pngImage;
}
