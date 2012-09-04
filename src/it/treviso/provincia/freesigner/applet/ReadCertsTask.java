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
import java.security.*;
import java.security.cert.*;
import java.util.*;

import javax.swing.JOptionPane;

import iaik.pkcs.pkcs11.*;
import iaik.pkcs.pkcs11.wrapper.*;
import it.treviso.provincia.freesigner.crl.*;
import it.trento.comune.j4sign.examples.SwingWorker;
import it.trento.comune.j4sign.pcsc.*;
import it.trento.comune.j4sign.pkcs11.*;
import it.treviso.provincia.freesigner.crl.CertificationAuthorities;

import org.bouncycastle.cms.*;

/**
 * This task reads certificates from token Task di lettura dei certifati da
 * token
 * 
 * @author Francesco Cendron
 */

public class ReadCertsTask extends AbstractTask {

	private String filepath;

	private String reader = null;

	private String cryptokiLib = null;

	private String cardDescription;

	private boolean isDownloadCRLForced = false;

	private int current;

	private String statMessage;

	private String CRLerror = "";

	private CertificationAuthorities CAroot = null;

	private boolean done;

	private boolean canceled;

	private int differentCerts;

	private ArrayList signersList;

	private CMSSignedData cms;

	private Hashtable risultati;

	private PKCS11Signer helper = null;

	private ArrayList slotInfos = null;

	private PCSCHelper pcsc;

	private java.util.List cards;

	private CardInReaderInfo cIr;

	private java.io.PrintStream log = null;

	public static final int ERROR = 0;

	public static final int SCAN_SLOTS = 1;

	public static final int READ_CERTS = 2;

	public static final int INIT_ROOTS = 3;

	public static final int VERIFY_CERTS = 4;

	private RootsVerifier rootsVerifier = null;

	/**
	 * Constructor
	 * 
	 * @param cIr
	 *            : Object containing information about card in reader
	 */

	public ReadCertsTask(String aReader, String aCryptoki,
			boolean isDownloadCRLForced) {

		log = System.out;
		this.isDownloadCRLForced = isDownloadCRLForced;
		signersList = new ArrayList();

		reader = aReader;

		cryptokiLib = aCryptoki;

	}

	public ReadCertsTask(String aReader, String aCryptoki,
			boolean isDownloadCRLForced, RootsVerifier rv) {

		this(aReader, aCryptoki, isDownloadCRLForced);
		this.rootsVerifier = rv;

	}

	public ArrayList getSlotInfos() {
		return slotInfos;
	}

	public void setSlotInfos(ArrayList slotInfos) {
		this.slotInfos = slotInfos;
	}

	public CardInReaderInfo getCIr() {
		return cIr;
	}

	public void setCIr(CardInReaderInfo cir) {

		try {

			if ((helper != null) && !cir.getLib().equals(getCryptokiLib())) {
				libFinalize();
			}

			if (helper.isLibFinalized())
				helper = new PKCS11Signer(cir.getLib(), log);

			helper.setTokenHandle(cir.getSlotId());

			cardDescription = cir.getCard().getProperty("description");
			setCryptokiLib(cir.getLib());

			this.cIr = cir;

		} catch (TokenException te) {
			setStatus(ERROR, "Eccezione Token: " + te);
			log.println(te);
		} catch (IOException e) {
			setStatus(ERROR, "Eccezione IO: " + e);
			log.println(e);
		}
	}

	/**
	 * Sets the cryptoki library name.
	 * 
	 * @param newCryptokiLib
	 *            String
	 */
	private void setCryptokiLib(java.lang.String newCryptokiLib) {
		cryptokiLib = newCryptokiLib;
	}

	/**
	 * Returns the cryptoki library name.
	 * 
	 * @return java.lang.String
	 */
	public java.lang.String getCryptokiLib() {
		return cryptokiLib;
	}

	/**
	 * Returns the PKCS11 helper.
	 * 
	 * @return PKCS11Signer
	 */
	public PKCS11Signer getPKCS11Signer() {
		return helper;
	}

	boolean isDone() {
		return done;
	}

	boolean isCanceled() {
		return canceled;
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

	String getFilePath() {
		return filepath;
	}

	CertificationAuthorities getCAroot() {
		return CAroot;
	}

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
		initCARoots();

		Security
				.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
		X509Certificate cert = null;

		risultati = new Hashtable();

		if (slotInfos != null) {

			Iterator slotsIterator = slotInfos.iterator();
			setStatus(VERIFY_CERTS, "Verifica certificati ...");

			while (slotsIterator.hasNext()) {

				Iterator certIterator = ((CardInReaderInfo) slotsIterator
						.next()).getCerts().iterator();

				while (certIterator.hasNext()) {

					cert = (X509Certificate) certIterator.next();
					System.out.println(" Verifiying signature from:\n"
							+ cert.getSubjectDN());

					setMessage("Verifica certificato:\n" + getCommonName(cert));
					CertValidity cv = new CertValidity(cert, CAroot,
							isDownloadCRLForced);

					// inserisce in una lista i DN dei firmatari
					signersList.add(cert.getSubjectDN());

					cv.getPassed();

					risultati.put(cert.getSubjectDN(), cv);
				}
			}
		}

	}

	/**
	 * Return Common name of given certificate<br>
	 * <br>
	 * Restituisce il CN del subjct certificato in oggetto
	 * 
	 * @param userCert
	 *            certificate
	 * @return CN
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

	public void go() {
		final SwingWorker worker = new SwingWorker() {
			public Object construct() {

				return new CertsFinder();

			}

		};
		worker.start();
	}

	/**
	 * The actual long running task. This runs in a SwingWorker thread. The goal
	 * of this task is finding all certificates on token
	 */
	class CertsFinder {

		/**
         * 
         */
		public CertsFinder() {
			log.println("CertsFinder running...");

			current = 1;
			done = false;
			canceled = false;

			slotInfos = scanSlots();

			if ((slotInfos == null) || slotInfos.isEmpty()) {
				done = true;
				return;
			}

			Iterator slotIterator = slotInfos.iterator();

			ArrayList certsOnSlot = null;
			int i = 0;
			while (slotIterator.hasNext()) {

				CardInReaderInfo currSlot = (CardInReaderInfo) slotIterator
						.next();

				if (currSlot.getCard() != null) {
					setCIr(currSlot);

					try {
						log.println(i
								+ ") Opening session on slot with handle "
								+ currSlot.getSlotId());
						helper.openSession();

						log.println("\tExtracting certificates...");
						CertsInfos certsAndHandles = getCertsOnToken();

						certsOnSlot = certsAndHandles.getCerts();
						differentCerts += certsOnSlot.size();

						currSlot.setCerts(certsOnSlot);
						// currSlot.setHandles(certsAndHandles.getHandles());
						currSlot.setIds(certsAndHandles.getIds());

						log.println(i
								+ ") Closing session on slot with handle "
								+ currSlot.getSlotId());
						helper.closeSession();
						i++;

					} catch (TokenException ex2) {
						log.println(ex2);
					}
				}
			}
			if ((differentCerts > 0) && (rootsVerifier != null))
				verify();

			// Evito di finalizzare la cryptoki;
			// Se si usano le informazioni (certHandle, tokenHandle )
			// qui accumulate per una firma successiva, ma con altro helper,
			// si ottiene un PKCS11 "General Error". Quindi si riutilizza
			// per la firma la presente istanza dell'helper PKCS11.

			// libFinalize();
			done = true;
		}

	}

	// ROB caricamento CA dal file firmato CNIPA.
	/**
	 * Inizializes CRL with CA file
	 * 
	 */

	public void initCARoots() {
		try {
			setStatus(INIT_ROOTS, "Caricamento CA ...");
			CAroot = this.rootsVerifier.getRoots(this);
		} catch (Exception ex) {
			setCanceled("Errore nell'inizializzazione delle CA: " + ex);
		}
	}

	void setStatus(int status, String message) {
		this.current = status;
		this.statMessage = message;
	}

	void setMessage(String message) {

		this.statMessage = message;
	}

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

	X509Certificate getCAcert(X509Certificate c)
			throws java.security.GeneralSecurityException {

		return CAroot.getCACertificate(c.getIssuerX500Principal());
	}

	public void selectTokenFromCertIndex(int certIndex) {
		Long tokenHandle = null;
		CardInReaderInfo slot = null;
		int i = 0;
		if (slotInfos != null) {

			Iterator slotsIterator = slotInfos.iterator();

			while (slotsIterator.hasNext()) {

				slot = (CardInReaderInfo) slotsIterator.next();
				Iterator certIterator = slot.getCerts().iterator();

				while (certIterator.hasNext()) {
					certIterator.next();
					if (i == certIndex) {
						setCIr(slot);
						return;
					}
					i++;
				}
			}
		}
	}

	/*
	 * public long getCertHandle(int certIndex) { Long handle = null;
	 * CardInReaderInfo slot = null; int i = 0; if (slotInfos != null) {
	 * 
	 * Iterator slotsIterator = slotInfos.iterator();
	 * 
	 * while (slotsIterator.hasNext()) {
	 * 
	 * slot = (CardInReaderInfo) slotsIterator.next(); Iterator handleIterator =
	 * slot.getHandles().iterator();
	 * 
	 * while (handleIterator.hasNext()) { handle = (Long) handleIterator.next();
	 * if (i == certIndex) return handle.longValue(); i++; } } }
	 * 
	 * return -1L;
	 * 
	 * }
	 */

	public byte[] getCertID(int certIndex) {
		byte[] id = null;
		CardInReaderInfo slot = null;
		int i = 0;
		if (slotInfos != null) {

			Iterator slotsIterator = slotInfos.iterator();

			while (slotsIterator.hasNext()) {

				slot = (CardInReaderInfo) slotsIterator.next();
				Iterator idIterator = slot.getIds().iterator();

				while (idIterator.hasNext()) {
					id = (byte[]) idIterator.next();
					if (i == certIndex)
						return id;
					i++;
				}
			}
		}

		return null;

	}

	/**
	 * Returns certificate handle with index i<br>
	 * <br>
	 * Ritorna l'handle del certificato con indice i
	 * 
	 * @param i
	 *            : index of chosen certificate( it is chosen in a table)
	 * @return long: cert handle
	 */

	public X509Certificate getCert(int certIndex) {
		X509Certificate cert = null;
		CardInReaderInfo slot = null;
		int i = 0;
		if (slotInfos != null) {

			Iterator slotsIterator = slotInfos.iterator();

			while (slotsIterator.hasNext()) {

				slot = (CardInReaderInfo) slotsIterator.next();
				Iterator certIterator = slot.getCerts().iterator();

				while (certIterator.hasNext()) {
					cert = (X509Certificate) certIterator.next();
					if (i == certIndex)
						return cert;
					i++;
				}
			}
		}

		return null;

	}

	// restituisce il certificato corrispondente al subject DN passato

	X509Certificate getCert(String DN) throws CMSException,
			java.security.NoSuchProviderException,
			java.security.NoSuchAlgorithmException, CertStoreException {

		X509Certificate cert = null;
		CardInReaderInfo slot = null;
		int i = 0;
		if (slotInfos != null) {

			Iterator slotsIterator = slotInfos.iterator();

			while (slotsIterator.hasNext()) {

				slot = (CardInReaderInfo) slotsIterator.next();
				Iterator certIterator = slot.getCerts().iterator();

				while (certIterator.hasNext()) {
					cert = (X509Certificate) certIterator.next();
					if (cert.getSubjectDN().toString().equals(DN))
						return cert;
					i++;
				}
			}
		}

		return null;
	}

	// ROB
	/**
	 * Finds the index associated to a certificate in this task.
	 * 
	 * Trova l'indice associato ad un certificato trovato in questo task.
	 * 
	 * 
	 * @author Roberto Resoli
	 */

	public int getCertIndex(String DN) {
		X509Certificate cert = null;
		CardInReaderInfo slot = null;
		int i = 0;
		if (slotInfos != null) {

			Iterator slotsIterator = slotInfos.iterator();

			while (slotsIterator.hasNext()) {

				slot = (CardInReaderInfo) slotsIterator.next();
				Iterator certIterator = slot.getCerts().iterator();

				while (certIterator.hasNext()) {
					cert = (X509Certificate) certIterator.next();
					if (cert.getSubjectDN().toString().equals(DN))
						return i;
					i++;
				}
			}
		}
		return -1;
	}

	/**
	 * Return a Collection of certificates present in token<br>
	 * <br>
	 * restituisce una Collection dei certificato presenti nel token
	 * 
	 * @return Collection
	 */
	private CertsInfos getCertsOnToken() {

		byte[] certBytes = null;

		java.security.cert.X509Certificate javaCert = null;
		CertificateFactory cf = null;

		ArrayList certsOnSlot = new ArrayList();
		ArrayList certsHandlesOnSlot = new ArrayList();
		ArrayList certsIDsOnSlot = new ArrayList();

		log.println("getCertsOnToken running ...");

		setStatus(READ_CERTS, "Lettura certificati su token:\n"
				+ getCardDescription());

		try {

			long[] certs = helper.findCertificates();

			if (certs != null) {
				try {
					cf = java.security.cert.CertificateFactory
							.getInstance("X.509");
				} catch (CertificateException ex) {

					log.println(ex);
				}
				java.io.ByteArrayInputStream bais = null;

				for (int i = 0; (i < certs.length); i++) {

					ByteArrayOutputStream certID = new ByteArrayOutputStream();
					log.println(i + ") Generating certificate with handle: "
							+ certs[i]);

					try {
						certBytes = helper.getDEREncodedCertificateAndID(
								certs[i], certID);
					} catch (PKCS11Exception ex2) {
						log.println(ex2);
					} catch (IOException e) {
						log.println(e);
					}
					bais = new java.io.ByteArrayInputStream(certBytes);

					try {
						javaCert = (java.security.cert.X509Certificate) cf
								.generateCertificate(bais);

						setMessage("Letto certificato\n"
								+ getCommonName(javaCert));

					} catch (CertificateException ex1) {
						log.println(ex1);
					}
					log.println(javaCert.getSubjectDN());

					certsOnSlot.add(javaCert);
					certsHandlesOnSlot.add(new Long(certs[i]));
					certsIDsOnSlot.add(certID.toByteArray());

				}

			} else {
				return null;
			}

		} catch (CertificateException ce) {
			log.println(ce);
		} catch (TokenException te) {
			log.println(te);
		}

		return new CertsInfos(certsOnSlot, certsHandlesOnSlot, certsIDsOnSlot);
	}

	public class CertsInfos {
		private ArrayList certs;

		private ArrayList handles;

		private ArrayList ids;

		public CertsInfos(ArrayList certsArray, ArrayList handlesArray,
				ArrayList idsArray) {
			this.certs = certsArray;
			this.handles = handlesArray;
			this.ids = idsArray;
		}

		public ArrayList getCerts() {
			return certs;
		}

		public ArrayList getHandles() {
			return handles;
		}

		public ArrayList getIds() {
			return ids;
		}

	}

	/**
	 * Return bytearray of file to sign<br>
	 * <br>
	 * Restituisce il bytearray del file da firmare
	 * 
	 * @return byte[]
	 */
	byte[] getFile() {
		return (byte[]) cms.getSignedContent().getContent();
	}

	/**
	 * Return hashtable with results<br>
	 * <br>
	 * Restituisce l'hashtable dei risultati
	 * 
	 * @return Hashtable
	 */
	Hashtable getRisultati() {
		return risultati;
	}

	/**
	 * Finalize helper
	 * 
	 */

	public void libFinalize() {
		try {
			if (helper != null && !helper.isLibFinalized()) {
				helper.libFinalize();
				log.println("Lib finalized.");
			}
		} catch (Throwable e1) {
			log.println("Error finalizing criptoki: " + e1);
		}

	}

	/**
	 * Return error message if any error occured during CRL download<br>
	 * <br>
	 * Restituisce il messaggio di errore CRLerror che capita durante il
	 * download della CRL
	 * 
	 * @return String
	 */
	public String getCRLerror() {

		return CRLerror;
	}

	/**
	 * Return description of read card Restituisce la descrizione della carta
	 * letta
	 * 
	 * @return String
	 */
	public String getCardDescription() {

		return cardDescription;
	}

	public int getDifferentCerts() {
		return differentCerts;
	}

	private ArrayList scanSlots() {

		setStatus(SCAN_SLOTS, "Scansione Tokens"
				+ ((reader == null) ? "" : " nel lettore\n" + reader) + " ...");
		ArrayList infos = findSlotsInfos(cryptokiLib);

		if (reader == null)
			return infos;
		else {
			Iterator it = infos.iterator();

			ArrayList readerInfos = new ArrayList();
			CardInReaderInfo cIrIn = new CardInReaderInfo();

			while (it.hasNext()) {
				cIrIn = (CardInReaderInfo) it.next();
				if (cIrIn.getReader().equals(reader))
					readerInfos.add(cIrIn);
			}

			return readerInfos;
		}

	}

	private ArrayList findSlotsInfos(String cryptoki) {

		ArrayList infos = new ArrayList();
		CardInfo ci = null;

		if (!(cryptoki== null || "".equals(cryptoki)))
			infos = findSlotsInfos(cryptoki, "FF", "Not available");
		else {

			PCSCHelper pcsc = new PCSCHelper(true);

			// Scansione di Lettri e carte (atr) via pkcs11
			java.util.List pcscInfos = pcsc.findCardsAndReaders();

			Iterator it = pcscInfos.iterator();

			ArrayList slotInfos = new ArrayList();

			while (it.hasNext()) {
				CardInReaderInfo cIr = (CardInReaderInfo) it.next();
				String currReader = cIr.getReader();

				ci = cIr.getCard();

				if (ci == null)
					infos.add(cIr);
				else {

					String desc = ci.getProperty("description");
					String atr = ci.getProperty("atr");
					String lib = ci.getProperty("lib");
					String manu = ci.getProperty("manufacturer");

					// Scansione degli slots utilizzando la lib pkcs11 candidata
					slotInfos = findSlotsInfos(lib, atr, manu);

					if (slotInfos != null) {
						Iterator it1 = slotInfos.iterator();

						while (it1.hasNext()) {
							CardInReaderInfo cIrPKCS11 = (CardInReaderInfo) it1
									.next();
							// Vengono aggiunte solo le informazioni relative
							// allo
							// specifico lettore
							if (currReader.equals(cIrPKCS11.getReader()))
								infos.add(cIrPKCS11);
						}
					}
				}
			}

		}

		return infos;
	}

	private ArrayList findSlotsInfos(String cryptoki, String atr,
			String manufacturer) {

		ArrayList infos = null;

		try {
			if (helper == null) {
				helper = new PKCS11Signer(cryptoki, log);
				cryptokiLib = cryptoki;
			}
			if (!cryptoki.equals(cryptokiLib)) {

				libFinalize();

				helper = new PKCS11Signer(cryptoki, log);

				cryptokiLib = cryptoki;

			}

			if (helper != null) {
				long[] tokens = helper.getTokens();
				String msg = tokens.length + " token rilevati con la lib "
						+ cryptoki;

				log.println(msg);
				setMessage(msg);

				infos = new ArrayList();

				for (int i = 0; i < tokens.length; i++) {

					CardInfo ci = new CardInfo();

					helper.setTokenHandle(tokens[i]);

					ci.addProperty("description", helper.getTokenDescription()
							.trim());
					ci.addProperty("atr", atr);
					ci.addProperty("lib", cryptoki);
					ci.addProperty("manufacturer", manufacturer);

					CardInReaderInfo cIr = new CardInReaderInfo(helper
							.getSlotDescription((long) tokens[i]).trim(), ci);

					cIr.setIndexToken(i);
					cIr.setSlotId(tokens[i]);
					cIr.setLib(cryptoki);

					infos.add(cIr);
				}
			}
		} catch (TokenException te) {
			System.out.println(te);
			setMessage(te.getMessage());
		} catch (IOException ioe) {
			System.out.println(ioe);
			setMessage(ioe.getMessage());
		} catch (Throwable e) {
			e.printStackTrace();
		}

		return infos;

	}
}
