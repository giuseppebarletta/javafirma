/**
 *	Freesigner - a j4sign-based open, multi-platform digital signature client
 *	Copyright (c) 2005 Francesco Cendron - Infocamere
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License
 *	as published by the Free Software Foundation; either version 2
 *	of the License, or (at your option) any later version.
 *
 *	This program is distributed in the hope that it will be useful,
 *	but WITHOUT ANY WARRANTY; without even the implied warranty of
 *	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *	GNU General Public License for more details.
 *
 *	You should have received a copy of the GNU General Public License
 *	along with this program; if not, write to the Free Software
 *	Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 *
 */

package it.treviso.provincia.freesigner.applet;

import java.io.*;
import java.net.URL;
import java.security.*;
import java.security.cert.*;
import java.util.*;

import javax.swing.JOptionPane;

import it.treviso.provincia.freesigner.crl.*;
import it.trento.comune.j4sign.examples.SwingWorker;
import it.treviso.provincia.freesigner.crl.CertificationAuthorities;

import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.cms.*;
import org.bouncycastle.openssl.PEMReader;
import org.bouncycastle.util.encoders.*;

/**
 * Verification task<br>
 * <br>
 * Task di verifica di file firmato
 * 
 * @author Francesco Cendron
 */

public class VerifyTask extends AbstractTask {

	private String filepath;

	private int current;

	private String statMessage;

	private CertificationAuthorities CAroot;

	private boolean done;

	private boolean canceled;

	private boolean passed;

	private int differentSigners;

	private ArrayList signersList;

	private Iterator currentSigner;

	private CMSSignedData cms;

	private Hashtable risultati;

	private String CRLerror = "";

	private String verifyError = "";

	private boolean isDownloadCRLForced;

	private RootsVerifier rootsVerifier = null;

	/**
	 * Constructor
	 * 
	 * @param f
	 *            : indirizzo file firmato
	 * 
	 */

	public VerifyTask(String f) {
		this(f, false);
	}

	/**
	 * Constructor
	 * 
	 * @param f
	 *            : address of signed file
	 * @param isDownloadCRLForced
	 *            : true if CRL download is forced
	 * 
	 */

	public VerifyTask(String f, boolean isDownloadCRLForced) {
		filepath = f;
		signersList = new ArrayList();
		this.isDownloadCRLForced = isDownloadCRLForced;
		readFile();
	}

	public VerifyTask(String f, boolean isDownloadCRLForced, RootsVerifier rv) {
		this(f, isDownloadCRLForced);
		this.rootsVerifier = rv;
	}

	/**
	 * Reads file and instantiate iterator currentSigner to deal with multiple
	 * signers <br>
	 * <br>
	 * Legge il file e recupera l'iteratore currentSigner che verrà usato per
	 * scorrere i vari firmatari
	 * 
	 * 
	 */

	public void readFile() {

		byte[] buffer = new byte[1024];

		FileInputStream is = null;
		try {
			is = new FileInputStream(this.filepath);
		} catch (FileNotFoundException ex) {
			setCanceled("Errore nell'acquisizione del file");
		}
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		try {
			while (is.read(buffer) > 0) {
				baos.write(buffer);
			}
		} catch (Exception ex) {
			setCanceled("Errore nella lettura del file");
		}

		byte[] risultato = baos.toByteArray();

		// Is file PEM, raw Base64 or DER encoded?
		byte[] certData = null;

		try {
			FileReader r = new FileReader(this.filepath);
			PEMReader pr = new PEMReader(r);
			ContentInfo ci = (ContentInfo) pr.readObject();
			r.close();

			this.cms = new CMSSignedData(ci);

		} catch (Exception e) {
			//ROB: trying raw base64 ...
			try { // se Base64, decodifica (italian law!) 
				certData = Base64.decode(risultato); 
				// Decodifica base64 completata 
				//setMessage("Il file firmato è in formato Base64");
			} catch (Exception eb64) { 
				// il file non e' in formato base64 //
				// quindi è in DER (againitalian law!) //
				// setMessage("Il file firmato è in formato DER");
				certData = risultato;
			}

		}
		// Estrazione del certificato dal file (ora codificato DER)
		try {
			if (certData != null)
				this.cms = new CMSSignedData(certData);
		} catch (CMSException ex1) {
			setCanceled("Errore nell'estrazione del certificato dal file");
			verifyError = "Errore nell'estrazione del certificato dal file";
		} catch (IllegalArgumentException ex1) {
			setCanceled("Errore nell'estrazione del certificato dal file");
			verifyError = "Errore nell'estrazione del certificato dal file";
		}
		if (verifyError.length() == 0) {
			Security
					.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
			// recupero dal CMS la lista dei certificati

			try {
				CertStore certs = cms
						.getCertificatesAndCRLs("Collection", "BC");
			} catch (CMSException ex2) {
				setCanceled("Errore nel CMS");
			} catch (NoSuchProviderException ex2) {
				setCanceled("Non esiste il provider del servizio");
			} catch (NoSuchAlgorithmException ex2) {
				setCanceled("Errore nell'algoritmo");
			}

			// Recupero i firmatari.
			SignerInformationStore signers = cms.getSignerInfos();

			Collection c = signers.getSigners();
			differentSigners = cms.getSignerInfos().size();

			// non avrebbe senso che fossero uguali
			// quindi fa il ciclo tra i firmatari
			// PERO' PUO' CAPITARE CHE CI SIA UN FIRMATARIO CHE FIRMA DUE VOLTE
			// E IN QUESTO CASO DOVREBBE FARE IL GIRO SUI CERTIFICATI!!!
			currentSigner = c.iterator();
			if (!currentSigner.hasNext()) {
				done = true;
			}
		} else {
			canceled = true;
		}
	}

	/**
	 * true if task is done<br>
	 * <br>
	 * true se task terminato
	 * 
	 * @return boolean
	 */
	boolean isDone() {
		return done;
	}

	/**
	 * true if task is canceled<br>
	 * <br>
	 * true se task canceled
	 * 
	 * @return boolean
	 */
	boolean isCanceled() {
		return canceled;
	}

	/**
	 * true if task successfully ended true se task passato con successo.<br>
	 * <br>
	 * 
	 * @return boolean
	 */
	boolean isPassed() {
		return passed;
	}

	/**
	 * Return the number of different signers<br>
	 * <br>
	 * Restituisce il numero dei firmatari
	 * 
	 * @return int
	 */
	int getDifferentSigners() {
		return differentSigners;
	}

	/**
	 * Returns String array of signers (used in combobox)<br>
	 * <br>
	 * restituisce un array di stringhe contenenti i firmatari (utilizzato nel
	 * combo box)
	 * 
	 * @return String[]
	 */

	String[] getSigners() {
		String[] s = new String[15];
		SignerInformationStore signers = cms.getSignerInfos();
		Collection c = signers.getSigners();

		Iterator it = signersList.listIterator();

		int i = 0;
		while (i != signersList.size()) {
			s[i] = signersList.get(i).toString();
			i++;
		}

		return s;
	}

	/**
	 * Return filePath of the file to verify<br>
	 * <br>
	 * Restituisce il file path del file da verificare
	 * 
	 * @return String
	 */
	String getFilePath() {
		return filepath;
	}

	/**
	 * Return the current signer<br>
	 * <br>
	 * Restituisce il nome del current signer
	 * 
	 * @return String
	 */
	String getCurrentSigner() {
		// ritorna solo l'ultimo
		return statMessage;
	}

	/**
	 * Executes all verifications on certificate<br>
	 * <br>
	 * Esegue le verifiche sul certificato
	 * 
	 */

	void verify() {
		Security
				.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
		X509Certificate cert = null;
		CertStore certs = null;

		passed = false;

		try {

			certs = this.cms.getCertificatesAndCRLs("Collection", "BC");

		} catch (CMSException ex2) {
			System.out.println("Errore nel CMS");
			setCanceled("Errore nel CMS");
		} catch (NoSuchProviderException ex2) {
			System.out.println("Non esiste il provider del servizio");
			setCanceled("Non esiste il provider del servizio");
		} catch (NoSuchAlgorithmException ex2) {
			System.out.println("Errore nell'algoritmo");
			setCanceled("Errore nell'algoritmo");
		}

		if (certs != null) {
			SignerInformation signer = (SignerInformation) currentSigner.next();

			Collection certCollection = null;
			try {
				certCollection = certs.getCertificates(signer.getSID());
			} catch (CertStoreException ex1) {
				setCanceled("Errore nel CertStore");
			}

			if (certCollection.size() == 1) {
				// Iterator certIt = certCollection.iterator();
				// X509Certificate cert = (X509Certificate)
				// certIt.next();

				cert = (X509Certificate) certCollection.toArray()[0];
				// CertValidity cv=new CertValidity(cert, CAroot);
				// System.out.println(i + ") Verifiying signature from:\n"
				// + cert.getSubjectDN());

				// inserisce in una lista i DN dei firmatari
				signersList.add(cert.getSubjectDN());

				setStatus(++current, "Verifica cerificato:\n"
						+ getCommonName(cert));

				VerifyResult vr = new VerifyResult(cert, cms, CAroot, signer,
						isDownloadCRLForced);
				passed = vr.getPassed();
				CRLerror = vr.getCRLerror();

				risultati.put(cert.getSubjectDN(), vr);
			} else {
				setCanceled("There is not exactly one certificate for this signer!");
			}
			if (!currentSigner.hasNext()) {
				done = true;
			}

		}

	}

	/**
	 * Return Common name of given certificate<br>
	 * <br>
	 * Restituisce il CN del subjct certificato in oggetto
	 * 
	 * @param userCert
	 *            certificato da cui estrarre il Common Name
	 * @return la stringa contenente il CN
	 */
	private static String getCommonName(X509Certificate userCert) {
		String DN = userCert.getSubjectDN().toString();
		int offset = DN.indexOf("CN=");
		int end = DN.indexOf(",", offset);
		String CN;
		if (end != -1) {
			CN = DN.substring(offset + 3, end);
		} else {
			CN = DN.substring(offset + 3, DN.length());
		}
		return CN;
	}

	/**
	 * Starts task<br>
	 * <br>
	 * Inizia il task
	 * 
	 */

	public void go() {
		final SwingWorker worker = new SwingWorker() {

			public Object construct() {

				return new ActualTask();
			}

		};
		worker.start();
	}

	// ROB caricamento CA dal file firmato CNIPA.
	/**
	 * Inizializes CRL with CA file
	 * 
	 */

	public void initCARoots() {
		try {
			setMessage("Verifica e caricamento CA ...");
			CAroot = this.rootsVerifier.getRoots(this);
		} catch (Exception ex) {
			setCanceled("Errore nell'inizializzazione delle CA: " + ex);
		}
	}

	class ActualTask {
		ActualTask() {

			current = 0;
			done = false;
			canceled = false;

			initCARoots();

			if (CAroot == null) {
				System.out.println("Errore nel CMS");
				setCanceled("Errore nel CMS");
				return;
			} else {
				risultati = new Hashtable();

				// Fake a long task,
				// making a random amount of progress every second.
				while (!canceled && !done) {
					try {
						verify();

					} catch (Exception e) {
						System.out.println("ActualTask interrupted " + e);
						canceled = true;
					}
				}
			}
		}
	}

	/**
	 * Set the status and message to be used in progressBar<br>
	 * <br>
	 * Setta l'intero status per segnare il progresso nella progressBar e il
	 * messaggio message da segnare sopra la progressBar
	 * 
	 * @param status
	 *            int
	 * @param message
	 *            String
	 */
	void setStatus(int status, String message) {
		this.current = status;
		this.statMessage = message;
	}

	/**
	 * Set message to be used in progressBar<br>
	 * <br>
	 * Setta il messaggio message da segnare sopra la progressBar
	 * 
	 * @param message
	 *            String
	 */
	void setMessage(String message) {

		this.statMessage = message;
	}

	/**
	 * Set canceled = true<br>
	 * <br>
	 * Setta canceled = true
	 * 
	 * @param message
	 *            String
	 */
	void setCanceled(String message) {
		this.statMessage = message;
		this.canceled = true;
	}

	String getMessage() {
		return statMessage;
	}

	int getStatus() {
		return current;
	}

	/**
	 * Return CA certificate that issued certificate c<br>
	 * <br>
	 * Restituisce il certificato della CA emettitrice del certificato c
	 * 
	 * @param c
	 *            X509Certificate
	 * @throws GeneralSecurityException
	 * @return X509Certificate
	 */
	X509Certificate getCAcert(X509Certificate c)
			throws java.security.GeneralSecurityException {

		return CAroot.getCACertificate(c.getIssuerX500Principal());
	}

	CertificationAuthorities getCAroot() {
		return CAroot;
	}

	/**
	 * Return certificate corresponding to DN<br>
	 * <br>
	 * restituisce il certificato corrispondente al DN passato ATTENZIONE! anche
	 * qui non si gestisce il caso di firma con 2 volte lo stesso cert
	 * 
	 * @param DN
	 *            String
	 * @throws CMSException
	 * @throws NoSuchProviderException
	 * @throws NoSuchAlgorithmException
	 * @throws CertStoreException
	 * @return X509Certificate
	 */
	X509Certificate getCert(String DN) throws CMSException,
			java.security.NoSuchProviderException,
			java.security.NoSuchAlgorithmException, CertStoreException {
		CertStore certs = this.cms.getCertificatesAndCRLs("Collection", "BC");

		// Recupero i firmatari.
		SignerInformationStore signers = this.cms.getSignerInfos();
		Collection c = signers.getSigners();

		Iterator it = c.iterator();

		// ciclo tra tutti i firmatari
		int i = 0;
		while (it.hasNext()) {
			SignerInformation signer = (SignerInformation) it.next();
			Collection certCollection = certs.getCertificates(signer.getSID());

			if (certCollection.size() == 1) {
				// Iterator certIt = certCollection.iterator();
				// X509Certificate cert = (X509Certificate)
				// certIt.next();

				X509Certificate cert = (X509Certificate) certCollection
						.toArray()[0];
				if (cert.getSubjectDN().toString().equals(DN)) {
					return cert;
				}
			} else {
				System.out
						.println("There is not exactly one certificate for this signer!");
			}
			i++;
		}
		return null;
	}

	byte[] getFile() {
		return (byte[]) cms.getSignedContent().getContent();
	}

	Hashtable getRisultati() {
		return risultati;
	}

	public String getCRLerror() {

		return CRLerror;
	}

	public String getVerifyError() {

		return verifyError;
	}

}
