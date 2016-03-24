//
// (C) 2013 Soffid
// 
// This file is licensed by Soffid under GPL v3 license
//

package com.soffid.iam.addons.selfcertificate.service;
import com.soffid.mda.annotation.*;

import org.springframework.transaction.annotation.Transactional;

@Service ( translatedName="SelfCertificateService",
	 translatedPackage="com.soffid.iam.addons.selfcertificate.service")
@Depends ({es.caib.seycon.ng.servei.ConfiguracioService.class,
	com.soffid.iam.addons.selfcertificate.model.SelfCertificateEntity.class,
	com.soffid.iam.addons.selfcertificate.model.RootCertificateEntity.class,
	es.caib.seycon.ng.model.UsuariEntity.class})
public abstract class SelfCertificateService {

	@Operation ( grantees={com.soffid.iam.addons.selfcertificate.roles.selfcertificate_query.class})
	@Transactional(rollbackFor={java.lang.Exception.class})
	public java.util.List<com.soffid.iam.addons.selfcertificate.common.SelfCertificate> findByUser(
		java.lang.String user)
		throws es.caib.seycon.ng.exception.InternalErrorException {
	 return null;
	}
	@Operation ( grantees={com.soffid.iam.addons.selfcertificate.roles.selfcertificate_query.class})
	@Transactional(rollbackFor={java.lang.Exception.class})
	public com.soffid.iam.addons.selfcertificate.common.SelfCertificate findByCertificate(
		java.security.cert.X509Certificate certificate)
		throws es.caib.seycon.ng.exception.InternalErrorException {
	 return null;
	}
	@Operation ( grantees={com.soffid.iam.addons.selfcertificate.roles.selfcertificate_user.class})
	@Transactional(rollbackFor={java.lang.Exception.class})
	public java.security.cert.X509Certificate create(
		java.lang.String description, 
		java.lang.String pkcs10)
		throws es.caib.seycon.ng.exception.InternalErrorException {
	 return null;
	}
	@Operation ( grantees={com.soffid.iam.addons.selfcertificate.roles.selfcertificate_user.class})
	@Transactional(rollbackFor={java.lang.Exception.class})
	public byte[] createPkcs12(
		java.lang.String description, 
		java.lang.String pasword)
		throws es.caib.seycon.ng.exception.InternalErrorException {
	 return null;
	}
	@Operation ( grantees={com.soffid.iam.addons.selfcertificate.roles.selfcertificate_manage.class,com.soffid.iam.addons.selfcertificate.roles.selfcertificate_user.class})
	@Transactional(rollbackFor={java.lang.Exception.class})
	public void revoke(
		com.soffid.iam.addons.selfcertificate.common.SelfCertificate cert)
		throws es.caib.seycon.ng.exception.InternalErrorException {
	}
	@Operation ( grantees={com.soffid.iam.addons.selfcertificate.roles.selfcertificate_manage.class})
	@Transactional(rollbackFor={java.lang.Exception.class})
	public com.soffid.iam.addons.selfcertificate.common.RootCertificate createRootCertificate(
		com.soffid.iam.addons.selfcertificate.common.RootCertificate root)
		throws es.caib.seycon.ng.exception.InternalErrorException {
	 return null;
	}
	@Operation ( grantees={com.soffid.iam.addons.selfcertificate.roles.selfcertificate_manage.class})
	@Transactional(rollbackFor={java.lang.Exception.class})
	public void updateRootCertificate(
		com.soffid.iam.addons.selfcertificate.common.RootCertificate root)
		throws es.caib.seycon.ng.exception.InternalErrorException {
	}
	@Operation ( grantees={com.soffid.iam.addons.selfcertificate.roles.selfcertificate_manage.class})
	@Transactional(rollbackFor={java.lang.Exception.class})
	public java.util.List<com.soffid.iam.addons.selfcertificate.common.RootCertificate> getRootCertificates()
		throws es.caib.seycon.ng.exception.InternalErrorException {
	 return null;
	}
	@Operation ( grantees={com.soffid.iam.addons.selfcertificate.roles.tothom.class})
	@Transactional(rollbackFor={java.lang.Exception.class})
	public java.security.cert.X509Certificate getRootCertificate()
		throws es.caib.seycon.ng.exception.InternalErrorException {
	 return null;
	}
	@Operation ( grantees={com.soffid.iam.addons.selfcertificate.roles.tothom.class})
	@Transactional(rollbackFor={java.lang.Exception.class})
	public int getUserCertificateDuration()
		throws es.caib.seycon.ng.exception.InternalErrorException {
	 return 0;
	}
	@Operation ( grantees={com.soffid.iam.addons.selfcertificate.roles.tothom.class})
	@Transactional(rollbackFor={java.lang.Exception.class})
	public java.util.List<com.soffid.iam.addons.selfcertificate.common.SelfCertificate> findMyCertificates()
		throws es.caib.seycon.ng.exception.InternalErrorException {
	 return null;
	}
}
