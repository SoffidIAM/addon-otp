//
// (C) 2013 Soffid
// 
// This file is licensed by Soffid under GPL v3 license
//

package com.soffid.iam.addons.selfcertificate.model;
import com.soffid.mda.annotation.*;

@Entity (table="SCS_CAROOT" )
@Depends ({com.soffid.iam.addons.selfcertificate.common.RootCertificate.class,
	com.soffid.iam.addons.selfcertificate.model.SelfCertificateEntity.class})
public abstract class RootCertificateEntity {

	@Column (name="CAR_CERTIF")
	public byte[] certificate;

	@Column (name="CAR_PRIKEY")
	public byte[] privateKey;

	@Column (name="CAR_ID")
	@Nullable
	@Identifier
	public java.lang.Long id;

	@Column (name="CAR_EXPDAT")
	public java.util.Date expirationDate;

	@Column (name="CAR_OBSOLE")
	public boolean obsolete;

	@Column (name="CAR_ORGNAM")
	public java.lang.String organizationName;

	@Column (name="CAR_USCEMO")
	public java.lang.Integer userCertificateMonths;

	@Column (name="CAR_CREDAT")
	public java.util.Date creationDate;

	@ForeignKey (foreignColumn="SCS_CAR_ID")
	public java.util.Collection<com.soffid.iam.addons.selfcertificate.model.SelfCertificateEntity> certificates;

}
