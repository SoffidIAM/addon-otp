//
// (C) 2013 Soffid
// 
// This file is licensed by Soffid under GPL v3 license
//

package com.soffid.iam.addons.selfcertificate.model;
import com.soffid.mda.annotation.*;

@Entity (table="SCS_SELCER" )
@Depends ({com.soffid.iam.addons.selfcertificate.common.SelfCertificate.class,
	es.caib.seycon.ng.model.UsuariEntity.class,
	com.soffid.iam.addons.selfcertificate.model.RootCertificateEntity.class})
public abstract class SelfCertificateEntity {

	@Column (name="SCS_ID")
	@Nullable
	@Identifier
	public java.lang.Long id;

	@Column (name="SCS_DESCRI", length=250)
	public java.lang.String description;

	@Column (name="SCS_EXPDAT")
	public java.util.Date expirationDate;

	@Column (name="SCS_USU_ID")
	public es.caib.seycon.ng.model.UsuariEntity user;

	@Column (name="SCS_CREDAT")
	public java.util.Date creationDate;

	@Column (name="REVOKED")
	public boolean revoked;

	@Column (name="SCE_CERTIF")
	public byte[] certificate;

	@Column (name="SCS_CAR_ID")
	@Nullable
	public com.soffid.iam.addons.selfcertificate.model.RootCertificateEntity root;

	@DaoFinder("select sce\nfrom com.soffid.iam.addons.selfcertificate.model.SelfCertificateEntityImpl as sce\n"
			+ "join sce.user as user\n"
			+ "where user.userName=:userName")
	public java.util.List<com.soffid.iam.addons.selfcertificate.model.SelfCertificateEntity> findByUser(
		java.lang.String userName) {
	 return null;
	}
	
	@DaoFinder
	public com.soffid.iam.addons.selfcertificate.model.SelfCertificateEntity findByCommonName(
		java.lang.String description) {
	 return null;
	}
}
