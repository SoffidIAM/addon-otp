//
// (C) 2013 Soffid
// 
// This file is licensed by Soffid under GPL v3 license
//

package com.soffid.iam.addons.selfcertificate.common;
import com.soffid.mda.annotation.*;

@ValueObject 
public class SelfCertificate {

	@Nullable
	public java.lang.Long id;

	public java.lang.String description;

	public java.util.Calendar expirationDate;

	public java.lang.String user;

	public java.util.Calendar creationDate;

	public boolean revoked;

	@Nullable
	public java.security.cert.X509Certificate certificate;

}
