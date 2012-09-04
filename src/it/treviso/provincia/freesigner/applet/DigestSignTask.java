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
import java.security.cert.*;

import iaik.pkcs.pkcs11.*;
import iaik.pkcs.pkcs11.wrapper.*;
import it.trento.comune.j4sign.pkcs11.*;

/** Uses a SwingWorker to perform signing task. */

public class DigestSignTask {
	private int lengthOfTask;

	private int current = 0;

	private boolean errorPresent = false;

	private String errorMsg;

	private String statMessage;

	private java.io.PrintStream log = null;

	private char[] password = null;

	private byte[] digest = null;

	private InputStream dataStream = null;

	private byte[] encryptedDigest;

	private String cryptoki = null;

	private PKCS11Signer helper = null;

	private String signerLabel = null;

//	private long certHandle = -1L;
	
	private byte[] certID = null;

	public static final int SIGN_MAXIMUM = 3;

	public static final int SIGN_INIT_SESSION = 0;

	public static final int SIGN_CERTIFICATE_INITDATA = 3;

	public static final int SIGN_ENCRYPT_DIGEST = 1;

	public static final int SIGN_DONE = 3;

	public static final int VERIFY_MAXIMUM = 2;

	public static final int VERIFY_INIT = 1;

	public static final int VERIFY_DONE = 2;

	public static final int RESET = 0;

	public static final int ERROR = -1;

	/**
	 * The actual long running task. This runs in a SwingWorker thread.
	 */
	class DigestSigner {

		DigestSigner() {
			errorPresent = false;

			try {

				setStatus(SIGN_INIT_SESSION, "Accesso alla carta...");
			//	Configuration conf = Configuration.getInstance();
				

				
			//	if (getDigest() != null) {
			//		log
			//				.println("digest is set, will use CKM_RSA_PKCS Mechanism");

					helper.setMechanism(PKCS11Constants.CKM_RSA_PKCS);
			/*	} else {
					log
							.println("digest is not set, will use CKM_MD5_RSA_PKCS Mechanism");
			
					helper.setMechanism(PKCS11Constants.CKM_MD5_RSA_PKCS);
				}*/

				encryptDigestAndGetCertificate(certID, helper);

				setStatus(SIGN_DONE, "Firma completata.");
				setPassword(null);

			} catch (CertificateException e) {
				log.println(e);
			};

		}

		/**
		 * Sign the certificate with handle aCertHandle.<br>
		 * <br>
		 * Firma il certificato con handle aCertHandle.
		 * 
		 * @param aCertHandle
		 *            handle of the certificate to be used
		 * @param helper
		 *            PKCS11Signer
		 * @throws CertificateException
		 */
		protected void encryptDigestAndGetCertificate(byte[] aCertID,
				PKCS11Signer helper) throws CertificateException {

			byte[] encrypted_digest = null;

			setStatus(SIGN_ENCRYPT_DIGEST, "Generazione della firma ...");
			try {
				try {
					errorPresent = false;
					helper.openSession(password);
				} catch (TokenException ex) {
					log.println("Messaggio helper.openSession(): "
							+ ex.getMessage());
					if (ex
							.toString()
							.startsWith(
									"iaik.pkcs.pkcs11.wrapper.PKCS11Exception: CKR_PIN_INCORRECT")
							|| ex.toString().startsWith("CKR_PIN_INCORRECT")) {
						errorPresent = true;
						errorMsg = "PIN sbagliato.";
						current = ERROR;

					}

					else if (ex.getMessage().startsWith("CKR_PIN_LOCKED")) {
						errorPresent = true;
						errorMsg = "PIN bloccato.";
					} else if (ex.getMessage().startsWith("CKR_PIN_LEN_RANGE")) {
						errorPresent = true;
						errorMsg = "PIN sbagliato: Lunghezza sbagliata.";
					} else if (ex.getMessage().startsWith(
							"CKR_TOKEN_NOT_RECOGNIZED")) {
						errorPresent = true;
						errorMsg = "CKR_TOKEN_NOT_RECOGNIZED.";
					} else if (ex.getMessage()
							.startsWith("CKR_FUNCTION_FAILED")) {
						errorPresent = true;
						errorMsg = "CKR_FUNCTION_FAILED.";
					}

					else if (ex.getMessage().startsWith("CKR_ARGUMENTS_BAD")) {
						errorPresent = true;
						errorMsg = "CKR_ARGUMENTS_BAD.";
					} else {

						// inserisci tutte le TokenException!!!
						errorPresent = true;
						errorMsg = "PKCS11Exception:\n" + ex.getMessage() + ".";
					}

				}

				log.println("User logged in.");

				long privateKeyHandle = -1L;
				long certHandle = -1;

				byte[] encDigestBytes = null;
				byte[] certBytes = null;

				log.println("Searching objects from ID ...");

				//certHandle = aCertHandle;

				if (certID != null) {
					//privateKeyHandle = helper.findSignatureKeyFromCertificateHandle(certHandle);
				    privateKeyHandle = helper.findSignatureKeyFromID(certID);
					if (privateKeyHandle > 0) {

						if (getDigest() != null) {
							encDigestBytes = helper.signDataSinglePart(
									privateKeyHandle, getDigest());
						} else {
							encDigestBytes = helper.signDataMultiplePart(
									privateKeyHandle, getDataStream());
						}
					}
					
					
					//certBytes = helper.getDEREncodedCertificate(certHandle);
					long currHandle = helper.findCertificateFromID(aCertID);
					
					log.println("old cert Handle:\t"+certHandle);
					log.println("new cert Handle:\t"+currHandle+"\n");
					
					certBytes = helper.getDEREncodedCertificate(currHandle);

					// log.println("\nEncrypted digest:\n" +
					// formatAsHexString(encDigestBytes));

					// log.println("\nDER encoded Certificate:\n" +
					// formatAsHexString(certBytes));

					setEncryptedDigest(encDigestBytes);
					setCertificate(certBytes);

				} else {
					log
							.println("\nNo private key corrisponding to certificate found on token!");
				}

			} catch (TokenException e) {
				log.println("sign() Error: " + e);
				// log.println(PKCS11Helper.decodeError(e.getCode()));
				// log.println(PKCS11Helper.decodeError(e.getCode()));

			} catch (IOException ioe) {
				log.println(ioe);
			} catch (UnsatisfiedLinkError ule) {
				log.println(ule);
			}
			logout();
		}

		/**
		 * Close PKCS11Signer session<br>
		 * <br>
		 * Chiude la sessione del PKCS11Signer.
		 * 
		 */

		public void closeSession() {
			if ((!errorPresent)) {
				if ((helper != null)) {
					try {
						helper.closeSession();
					} catch (PKCS11Exception ex) {
					}
				}
			}
		}

		/**
		 * Finalize PKCS11Signer<br>
		 * <br>
		 * Finalizza il PKCS11Signer.
		 * 
		 */
		public void libFinalize() {
			if ((!errorPresent)) {
				if ((helper != null)) {
					try {
						helper.libFinalize();
						log.println("Lib finalized.");
					} catch (Throwable e1) {
						log.println("Error finalizing criptoki: " + e1);
					}

				}
			}
		}

		/**
		 * Log out from PKCS11Signer session<br>
		 * <br>
		 * log out dalla sessione di PKCS11Signer.
		 * 
		 */
		public void logout() {
			if ((!errorPresent)) {
				if ((helper != null)) {
					try {
						helper.logout();
					} catch (PKCS11Exception ex1) {
					}
					log.println("User logged out.");

					helper = null;
					System.gc();
				}
			}
		}

		/*
		 * protected void getCertificateFromSmartCard(String signerLabel,
		 * PKCS11Helper helper) throws TokenException {
		 * 
		 * byte[] signerCert = null;
		 * 
		 * log.println("Finding certificate...");
		 * 
		 * helper.login(String.valueOf(password)); log.println("User logged
		 * in.");
		 * 
		 * setStatus(SIGN_CERTIFICATE_INITDATA, "Recupero certificato ...");
		 * 
		 * signerCert = helper.getCertificateBytes(signerLabel);
		 * 
		 * helper.logout(); log.println("User logged out.");
		 * 
		 * if (signerCert == null) { setStatus(ERROR, "Certificato non
		 * trovato!"); log.println("Certificate not found!"); }
		 * 
		 * setCertificate(signerCert); }
		 */

	} // end of nested class

	private byte[] certificate = null;

	DigestSignTask(String aCriptoki, String aSignerLabel,
			java.io.PrintStream aLog) {
		lengthOfTask = SIGN_MAXIMUM;
		this.log = aLog;
		this.cryptoki = aCriptoki;
		this.signerLabel = aSignerLabel;
	}

	DigestSignTask(PKCS11Signer aHelper, byte[] aCertID, java.io.PrintStream aLog) {
		lengthOfTask = SIGN_MAXIMUM;
		this.log = aLog;
	
		this.helper = aHelper;
		this.cryptoki = helper.getCryptokiLibrary();
//		this.certHandle = aCertHandle;	
		this.certID = aCertID;
		
	}



	/**
	 * Called from ProgressBarDemo to find out if the task has completed.
	 * 
	 * @return boolean
	 */
	boolean done() {
		if ((current >= lengthOfTask) || (current == ERROR)) {
			return true;
		} else {
			return false;
		}
	}

	/**
	 * Returns certificate in bytes[]<br>
	 * <br>
	 * restituisce il certificato in byte[]
	 * 
	 * @return certificate
	 */
	public byte[] getCertificate() {
		return certificate;
	}

	/**
	 * Called from ProgressBarDemo to find out how much has been done.
	 * 
	 * @return int
	 */
	int getCurrent() {
		return current;
	}

	/**
	 * 
	 * @return byte[]
	 */
	public byte[] getDigest() {

		return this.digest;
	}

	/**
	 * 
	 * 
	 * @return byte[]
	 */
	public byte[] getEncryptedDigest() {
		return this.encryptedDigest;
	}

	/**
	 * Called from ProgressBarDemo to find out how much work needs to be done.
	 * 
	 * @return int
	 */
	int getLengthOfTask() {
		return lengthOfTask;
	}

	String getMessage() {
		return statMessage;
	}

	/**
	 * Called from Signer Application to start the task.
	 */
	void go() {
		current = 0;

		final SwingWorker worker = new SwingWorker() {
			public Object construct() {
				return new DigestSigner();
			}
		};
		worker.start();

	}

	/**
	 * 
	 * @param newCertificate
	 *            int
	 */
	private void setCertificate(byte[] newCertificate) {
		certificate = newCertificate;
	}

	/**
	 * 
	 * 
	 * @param newDigest
	 *            byte[]
	 */
	public void setDigest(byte[] newDigest) {
		this.digest = newDigest;
	}

	/**
	 * 
	 * 
	 * @param newEncryptedDigest
	 *            iaik.pkcs.pkcs7.SignedData
	 */
	private void setEncryptedDigest(byte[] newEncryptedDigest) {
		encryptedDigest = newEncryptedDigest;
	}

	/**
	 * 
	 * 
	 * @param pwd
	 *            char[]
	 */
	public void setPassword(char[] pwd) {
		this.password = pwd;
	}

	/**
	 * Set status and message to be used in ProgressBar Setta lo stato status e
	 * il message per la ProgressBar
	 * 
	 * @param status
	 *            int
	 * @param message
	 *            String
	 */
	private void setStatus(int status, String message) {
		this.current = status;
		this.statMessage = message;
	}

	void stop() {
		current = lengthOfTask;
	}

	public boolean error() {
		return errorPresent;
	}

	public String getErrorMsg() {
		return errorMsg;
	}

	public InputStream getDataStream() {
		return dataStream;
	}

	public void setDataStream(InputStream dataStream) {
		this.dataStream = dataStream;
	}
}
