//
// (C) 2013 Soffid
//
//

package com.soffid.iam.addons.selfcertificate.model;

import java.io.ByteArrayInputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import com.soffid.iam.addons.selfcertificate.common.SelfCertificate;

/**
 * DAO SelfCertificateEntity implementation
 */
public class SelfCertificateEntityDaoImpl extends SelfCertificateEntityDaoBase
{

	@Override
	public void toSelfCertificate(SelfCertificateEntity source,
			SelfCertificate target) {
		super.toSelfCertificate(source, target);
		target.setUser(source.getUser() == null ? null: source.getUser().getUserName());
		try {
			CertificateFactory cf = CertificateFactory.getInstance("X.509");
			ByteArrayInputStream in = new ByteArrayInputStream(source.getCertificate());
			target.setCertificate( (X509Certificate) cf.generateCertificate(in));
		} catch (CertificateException e) {
		}
	}

	@Override
	public void selfCertificateToEntity(SelfCertificate source,
			SelfCertificateEntity target, boolean copyIfNull) {
		super.selfCertificateToEntity(source, target, copyIfNull);
		if (source.getUser() == null)
			target.setUser(null);
		else
		{
			target.setUser( getUserEntityDao().findByUserName(source.getUser()));
		}
	}
}
