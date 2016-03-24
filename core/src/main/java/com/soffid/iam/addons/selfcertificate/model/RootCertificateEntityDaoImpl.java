//
// (C) 2013 Soffid
//
//

package com.soffid.iam.addons.selfcertificate.model;

import java.io.ByteArrayInputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import com.soffid.iam.addons.selfcertificate.common.RootCertificate;

/**
 * DAO RootCertificateEntity implementation
 */
public class RootCertificateEntityDaoImpl extends RootCertificateEntityDaoBase
{

	@Override
	public void toRootCertificate(RootCertificateEntity source,
			RootCertificate target) {
		super.toRootCertificate(source, target);
		try {
			CertificateFactory cf = CertificateFactory.getInstance("X.509");
			ByteArrayInputStream in = new ByteArrayInputStream(source.getCertificate());
			target.setCertificate( (X509Certificate) cf.generateCertificate(in));
		} catch (CertificateException e) {
		}
	}
}
