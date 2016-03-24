package com.soffid.iam.addons.selfcertificate.ss;

import java.io.IOException;
import java.security.cert.X509Certificate;

import javax.naming.InitialContext;
import javax.servlet.ServletException;
import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.soffid.iam.addons.selfcertificate.common.SelfCertificate;
import com.soffid.iam.addons.selfcertificate.service.ejb.SelfCertificateService;
import com.soffid.iam.addons.selfcertificate.service.ejb.SelfCertificateServiceHome;

import es.caib.seycon.util.Base64;

public class GenerateCertificateServlet extends HttpServlet {

	public GenerateCertificateServlet() {
	}

	@Override
	protected void doPost(HttpServletRequest req, HttpServletResponse resp)
			throws ServletException, IOException {
		try {
			String pkcs10 = req.getParameter("pkcs10");
			String name = req.getParameter("name");
			SelfCertificateServiceHome home = (SelfCertificateServiceHome) new InitialContext()
					.lookup(SelfCertificateServiceHome.JNDI_NAME);
			SelfCertificateService svc = home.create();
			X509Certificate cert = svc.create(name, pkcs10);

			X509Certificate rootCert = svc.getRootCertificate();
			new CertificateSender ().send (req, resp, cert, rootCert); 
		} catch (Exception e) {
			throw new ServletException (e);
		}
	}

}
