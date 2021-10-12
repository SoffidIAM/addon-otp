package com.soffid.iam.addons.otp.web;

import org.zkoss.zk.ui.event.Event;

import com.soffid.iam.web.component.FrameHandler;

import es.caib.seycon.ng.exception.InternalErrorException;
import es.caib.zkib.component.DataTable;
import es.caib.zkib.datasource.CommitException;
import es.caib.zkib.datasource.XPathUtils;
import es.caib.zkib.zkiblaf.Application;
import es.caib.zkib.zkiblaf.Frame;

public class ConfigurationHandler extends FrameHandler {
	private static final long serialVersionUID = 1L;

	public ConfigurationHandler() throws InternalErrorException {
		super();
	}

	public void commit(Event event) throws CommitException {
		if (applyNoClose(event))
			Application.goBack();
	}
}
