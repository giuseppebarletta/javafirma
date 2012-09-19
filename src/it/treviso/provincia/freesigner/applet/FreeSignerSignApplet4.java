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

import it.treviso.provincia.freesigner.applet.FreesignerVerifyFrame2;

import java.io.*;
import java.security.*;
import java.util.*;

import javax.swing.*;

import org.bouncycastle.cms.*;
import org.bouncycastle.util.encoders.*;

import netscape.javascript.JSObject;


/**
 * GUI of signing operation
 *
 * @author Luca Lorenzetto (original version Francesco Cendron)
 */
public class FreeSignerSignApplet4 extends JFrame {


		/**
	 * 
	 */
	private static final long serialVersionUID = 1L;
		private JSObject jso;

		/**
         * Constructor
         *
         */

    public FreeSignerSignApplet4() {
        fileDaAprire = "";
        this.doSave();
    }

    /**
     * Constructor
     *
     * @param filepath String
     */
    public FreeSignerSignApplet4(String filepath, String callBackUrl) {
        fileDaAprire = new String(filepath);
        this.callBackUrl = callBackUrl;
        this.doSave();
    }

    /**
     * Constructor
     *
     * @param c cms
     * @param filepath String
     * @param t task ReadCertsTask
     * @param selected index of selected cert
     * @param jso 
     */
    public FreeSignerSignApplet4(CMSSignedData c, String filepath, ReadCertsTask t, String callBackUrl,
                    int selected, JSObject jso) {
        fileDaAprire = new String(filepath);
        cms = c;
        this.callBackUrl = callBackUrl;
        log = System.out;
        this.jso = jso;
        this.doSave();
        
    }

    /**
     * Saves bytearray to file
     *
     * @return true if it saved
     * @param bytes byte[]
     * @param to_file File
     * @throws IOException
     */
    public static boolean save(byte[] bytes, File to_file) throws
            IOException {
        boolean saved = false;
        int q = JOptionPane.YES_OPTION;
        if (to_file.exists()) {
            if (!to_file.canWrite()) {
                abort("Il file non ha i\npermessi di scrittura.");
            }
            // Ask whether to overwrite it
            q = JOptionPane.showConfirmDialog(
                    null,
                    "Il file esiste.\nSovrascriverlo?",
                    "Attenzione",
                    JOptionPane.YES_NO_OPTION);

            // Check the response.  If not a Yes, abort the copy.
            if (q == JOptionPane.NO_OPTION) {
                //non sovrascrivere
                return saved;
            }
        }
        if (q == JOptionPane.YES_OPTION) {

            FileOutputStream to = null; // Stream to write to destination

            ByteArrayInputStream bais = new ByteArrayInputStream(bytes);
            to = new FileOutputStream(to_file); // Create output stream
            byte[] buffer = new byte[4096]; // A buffer to hold file contents
            int bytes_read; // How many bytes in buffer
            // Read a chunk of bytes into the buffer, then write them out,
            // looping until we reach the end of the file (when read() returns -1).
            // Note the combination of assignment and comparison in this while
            // loop.  This is a common I/O programming idiom.
            while ((bytes_read = bais.read(buffer)) != -1) { // Read bytes until EOF
                to.write(buffer, 0, bytes_read); //   write bytes
            }
            to.close();
            //abort("Il file è stato salvato.");
            saved = true;

        }
        return saved;
    }

    /**
     * Method invoked for saving
     */
    
    public void doSave() {
        log.println("Saving signed message");

        String p7mFilePath = fileDaAprire + ".p7m";
        File file = new File(p7mFilePath);

            try {
                 saved = save(Base64.encode(cms.getEncoded()), file);
            } catch (IOException ex1) {
            	JOptionPane.showMessageDialog(null, "Errore di I/O durante il salvataggio di "+p7mFilePath, "Errore", JOptionPane.ERROR_MESSAGE);
            }

            if (saved) {
                log.println("Signed message saved to: "
                            + file.getAbsolutePath());                
                
                MessageDigest mdigest;
                String mhash  = "";
				try {
					mdigest = MessageDigest.getInstance("SHA-512");
					mhash = calculateHash(mdigest, p7mFilePath);
				} catch (Exception e2) {
					e2.printStackTrace();
				}
				
				jso.eval("window.location.href='"+callBackUrl+"&mhash="+mhash+"'");
				

            }
    }

    
    /**
     * A convenience method
     *
     * @param msg String
     */
    private static void abort(String msg) {
        JOptionPane.showMessageDialog(null,
                                      msg,
                                      "Attenzione",
                                      JOptionPane.INFORMATION_MESSAGE);

    }
    
    
    /**
     * hash calculators convenience method
     */

    private static String calculateHash(MessageDigest algorithm,
            String fileName) throws Exception{

        FileInputStream     fis = new FileInputStream(fileName);
        BufferedInputStream bis = new BufferedInputStream(fis);
        DigestInputStream   dis = new DigestInputStream(bis, algorithm);

        // read the file and update the hash calculation
        while (dis.read() != -1);

        // get the hash value as byte array
        byte[] hash = algorithm.digest();

        return byteArray2Hex(hash);
    }

    /**
     * Converts in base 64 i byte in input
     * @param hash
     * @return
     */
    private static String byteArray2Hex(byte[] hash) {
        Formatter formatter = new Formatter();
        for (byte b : hash) {
            formatter.format("%02x", b);
        }
        return formatter.toString();
    }


  
    private boolean saved = false;
    private String fileDaAprire;

    private CMSSignedData cms;
    private String callBackUrl;

    private java.io.PrintStream log = null;


}
