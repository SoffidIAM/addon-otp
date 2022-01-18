//
// (C) 2013 Soffid
// 
// This file is licensed by Soffid under GPL v3 license
//

package com.soffid.iam.addons.otp.model;
import java.util.Date;

import com.soffid.iam.addons.otp.common.OtpDeviceType;
import com.soffid.iam.addons.otp.common.OtpStatus;
import com.soffid.iam.model.TenantEntity;
import com.soffid.mda.annotation.*;

import es.caib.seycon.ng.model.MaquinaEntity;
import es.caib.seycon.ng.model.UsuariEntity;

@Entity (table="SCO_DEVICE" )
@Depends ({com.soffid.iam.addons.otp.common.OtpDevice.class,
	es.caib.seycon.ng.model.UsuariEntity.class})
public abstract class OtpDeviceEntity {
	@Column (name="OTP_TEN_ID")
	TenantEntity tenant;

	@Column (name="OTP_ID")
	@Nullable
	@Identifier
	public java.lang.Long id;

	@Column (name="OTP_NAME", length=250)
	@Nullable
	public java.lang.String name;

	@Column(name="OTP_TYPE")
	OtpDeviceType type;
	
	@Column (name="OTP_USU_ID", cascadeDelete=true)
	public UsuariEntity user;
	
	@Column (name="OTP_CREATED")
	public java.util.Date created;

	@Nullable
	@Column (name="OTP_LASUSE")
	public java.util.Date lastUsed;

	@Column (name="OTP_AUTKEY")
	@Nullable
	public String authKey;
	
	@Description("Contains the last counter value used to login")
	@Column (name="OTP_LASCOU")
	@Nullable
	public Long lastUsedValue;
	
	@Description("The last time a SMS was sent")
	@Column (name="OTP_LASISS")
	@Nullable
	public Date lastIssued;
	
	@Description("Failed attepms")
	@Column (name="OTP_FAILS")
	int fails;

	@Description("Status")
	@Column(name="OTP_STATUS", defaultValue = "com.soffid.iam.addons.otp.common.OtpStatus.CREATED")
	OtpStatus status ;

	@Description("Target Email")
	@Column (name="OTP_EMAIL")
	@Nullable
	String email;


	@Description("Target mobile phone")
	@Column (name="OTP_PHONE")
	@Nullable
	String phone;

	@Description("User PIN")
	@Column (name="OTP_PIN")
	@Nullable
	String pin;

	@Description("Number of digits otp")
	@Column (name="OTP_DIGITS")
	@Nullable
	Integer digits;


	@Description("OTP ALgorithm")
	@Column (name="OTP_ALGORI")
	@Nullable
	String algorithm;



	@DaoFinder("select sce\n"
			+ "from com.soffid.iam.addons.otp.model.OtpDeviceEntity as sce\n"
			+ "join sce.user as user\n"
			+ "where user.userName=:userName and user.tenant.id=:tenantId")
	public java.util.List<com.soffid.iam.addons.otp.model.OtpDeviceEntity> findByUser(
		java.lang.String userName) {
	 return null;
	}
	
	@DaoFinder("select sce\n"
			+ "from com.soffid.iam.addons.otp.model.OtpDeviceEntity as sce\n"
			+ "join sce.user as user\n"
			+ "where user.userName=:userName and user.tenant.id=:tenantId and sce.status='V'")
	public java.util.List<com.soffid.iam.addons.otp.model.OtpDeviceEntity> findEnabledByUser(
		java.lang.String userName) {
	 return null;
	}
}
