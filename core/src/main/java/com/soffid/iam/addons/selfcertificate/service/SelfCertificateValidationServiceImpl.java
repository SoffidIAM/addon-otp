package com.soffid.iam.addons.selfcertificate.service;

import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Collection;
import java.util.Date;
import java.util.LinkedList;
import java.util.List;

import com.soffid.iam.addons.selfcertificate.common.RootCertificate;
import com.soffid.iam.addons.selfcertificate.common.SelfCertificate;
import com.soffid.iam.addons.selfcertificate.model.RootCertificateEntity;
import com.soffid.iam.addons.selfcertificate.model.SelfCertificateEntity;
import com.soffid.iam.api.User;

import es.caib.seycon.ng.comu.Account;
import es.caib.seycon.ng.comu.Usuari;

public class SelfCertificateValidationServiceImpl extends
		SelfCertificateValidationServiceBase {

	public SelfCertificateValidationServiceImpl() {
	}

	@Override
	protected com.soffid.iam.api.Account handleGetCertificateAccount(List<X509Certificate> certs)
			throws Exception {
		return null;
	}

	private boolean validate (SelfCertificate cert)
	{
		if (cert == null)
			return false;
		if (cert.isRevoked())
			return false;
		Date now = new Date ();
		if (now.after(cert.getExpirationDate().getTime()))
			return false;
		if (now.before(cert.getCreationDate().getTime()))
			return false;
		SelfCertificateEntity certEntity = getSelfCertificateEntityDao().load(cert.getId());
		if (certEntity.getRoot() == null)
			return false;
		RootCertificateEntity root = certEntity.getRoot();
		if (root.isObsolete())
			return false;
		
		Calendar c = Calendar.getInstance();
		c.setTime(root.getExpirationDate());
		c.add(Calendar.MONTH, root.getUserCertificateMonths());
		if (now.after(c.getTime()))
			return false;
		
		return true;
	}
	
	@Override
	protected User handleGetCertificateUser(List<X509Certificate> certs)
			throws Exception {
		SelfCertificate cert = getSelfCertificateService().findByCertificate(certs.get(0));
		if (validate(cert))
		{
			return getUserService().findUserByUserName(cert.getUser());
		}
		else
			return null;
		
	}

	@Override
	protected Collection<X509Certificate> handleGetRootCertificateList()
			throws Exception {
		LinkedList<X509Certificate> certs = new LinkedList<X509Certificate>();
		for (RootCertificate cert: getSelfCertificateService().getRootCertificates())
		{
			if (! cert.isObsolete())
				certs.add(cert.getCertificate());
		}
		return certs;
	}

	@Override
	protected boolean handleValidateCertificate(List<X509Certificate> certs)
			throws Exception {
		SelfCertificate cert = getSelfCertificateService().findByCertificate(certs.get(0));
		return validate(cert);
	}

}
