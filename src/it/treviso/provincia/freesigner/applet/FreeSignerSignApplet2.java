package it.treviso.provincia.freesigner.applet;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Principal;
import java.security.cert.CertStoreException;
import java.util.Date;
import java.util.Iterator;
import java.util.Set;

import netscape.javascript.JSObject;

import org.bouncycastle.asn1.*;
import org.bouncycastle.cms.*;

public class FreeSignerSignApplet2 {
	
	private ReadCertsTask task;
	private String fileName;
	private String cb;
	private JSObject jso;

	public FreeSignerSignApplet2(ReadCertsTask t, String f,String cb, JSObject jso) {
			this.cb = cb;
			task = t;
			fileName = f;
			this.jso = jso;
			chooseCert();
			
	}
	
	public FreeSignerSignApplet2(ReadCertsTask t) {
		this(t,"","",null);
	}

	private void chooseCert() {
		while (!task.isDone()) {
			System.out.println("undone");
		}
		for (int i = 0; i<task.getDifferentCerts();i++) {
			DERBitString dbs = null;
			try {
				dbs = new DERBitString(task.getCertID(i));
			/*} catch (CertStoreException ex) {
				System.out.println(ex);
			} catch (NoSuchAlgorithmException ex) {
				System.out.println(ex);
			} catch (NoSuchProviderException ex) {
				System.out.println(ex);
			} catch (CMSException ex) {
				System.out.println(ex);
			}*/
			} catch (Exception e) {
				e.printStackTrace();
			}
			String usage = new String();
			usage = dbs.getString();
			System.out.println();
			String hexusage = usage.substring(usage.length() - 2, usage
					.length());

			usage = Integer.toBinaryString(Integer.parseInt(hexusage, 16));
			while (usage.length() < 8) {
				usage = "0" + usage;
			}
			
			System.out.println("Usage String: "+usage);
			
//			if (task.getCert(i).getNotAfter().after(new Date()))
			if ((usage.substring(1, 2)).equals("0") && task.getCert(i).getNotAfter().after(new Date()))
			{
				// certificato con la coccarda!
				System.out.println("Non ripudio ed in corso di validità");
				try {
					FreeSignerSignApplet3 frame = new FreeSignerSignApplet3(fileName,task, cb, i,jso);
				} catch (FileNotFoundException e) {
					System.err.println("E: Il file "+fileName+" non esiste");
				} catch (GeneralSecurityException e) {
					e.printStackTrace();
				} catch (IOException e) {
					System.err.println("E: Impossibile aprire il file "+fileName+".");
				} catch (CMSException e) {
					e.printStackTrace();
				}
				break;
			} else System.out.println("altra funzionalità o scaduta");
		}
		
	}
	
}
