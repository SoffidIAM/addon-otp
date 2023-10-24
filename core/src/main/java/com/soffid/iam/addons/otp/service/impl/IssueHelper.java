package com.soffid.iam.addons.otp.service.impl;

import java.io.IOException;
import java.util.Arrays;
import java.util.Date;

import com.soffid.iam.api.Issue;
import com.soffid.iam.api.IssueStatus;
import com.soffid.iam.api.IssueUser;
import com.soffid.iam.service.IssueService;

import es.caib.seycon.ng.exception.InternalErrorException;

public class IssueHelper {

	public static void lockOtp(Long userId, String otpDevice) throws InternalErrorException, IOException {
		IssueService svc = com.soffid.iam.ServiceLocator.instance().getIssueService();
		Issue i = new Issue();
		i.setCreated(new Date());
		i.setStatus(IssueStatus.NEW);
		i.setType("otp-failures");
		IssueUser iu = new IssueUser();
		iu.setUserId(userId);
		i.setUsers(Arrays.asList(iu));
		i.setOtpDevice(otpDevice);
		i.setHash(otpDevice);
		svc.createInternalIssue(i);
	}

}
