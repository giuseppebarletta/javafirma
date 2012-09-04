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

import java.awt.*;
import java.awt.event.*;
import java.io.*;
import java.security.*;

import javax.swing.*;

import org.bouncycastle.cms.*;

/**
 * GUI for signature verification.
 * 
 * @author Francesco Cendron
 */
public class FreesignerVerifyFrame2 extends JFrame {

    /**
     * Constructor
     * 
     * @param filepath
     *            String
     * @throws GeneralSecurityException
     * @throws FileNotFoundException
     * @throws IOException
     * @throws CMSException
     */
    public FreesignerVerifyFrame2(String filepath)
            throws GeneralSecurityException, FileNotFoundException,
            IOException, CMSException {
        this(filepath, false);
    }

    /**
     * Constructor
     * 
     * @param filepath
     *            String
     * @param isDownloadCRLForced
     *            boolean
     * @throws GeneralSecurityException
     * @throws FileNotFoundException
     * @throws IOException
     * @throws CMSException
     */
    public FreesignerVerifyFrame2(String filepath, boolean isDownloadCRLForced)
            throws GeneralSecurityException, FileNotFoundException,
            IOException, CMSException {

        fileDaAprire = new String(filepath);

        frame = new JFrame();

        RootsVerifier rv = RootsVerifier.getInstance();

        task = new VerifyTask(fileDaAprire, isDownloadCRLForced, rv);

        if (rv.getUserApprovedFingerprint() != null) {
            task.go();

            initComponents();

            timer.start();
        } else {

            JOptionPane
                    .showMessageDialog(
                            this,
                            "Il certificato di firma del file delle CA è stato rifiutato.\n"
                                    + "La lista delle autorità di certificazione non risulta quindi affidabile.\n",
                            "Impossibile continuare.",
                            JOptionPane.WARNING_MESSAGE);

            frame.hide();
            FreeSignerSignApplet nuovo = new FreeSignerSignApplet();
        }

    }

    /**
     * Inizialize frame components
     * 
     * @throws CMSException
     * @throws FileNotFoundException
     * @throws IOException
     * @throws GeneralSecurityException
     */
    private void initComponents() throws CMSException, FileNotFoundException,
            IOException, GeneralSecurityException {
        timer = new Timer(100, new ActionListener() {
            public void actionPerformed(ActionEvent evt) {
                if (task.getVerifyError().length() > 0) {

                    JOptionPane.showMessageDialog(frame,
                            "Il file non è in formato busta crittografica.\n"
                                    + task.getVerifyError(),
                            "Errore lettura file firmato",
                            JOptionPane.WARNING_MESSAGE);
                    frame.hide();
                    timer.stop();
                    //FreesignerVerifyFrame1 nuovo = new FreesignerVerifyFrame1();

                }
                if (task.getMessage() != null) {
                    String s = new String();
                    s = task.getMessage();
                    s = s.substring(0, Math.min(60, s.length()));

                    textArea2.setText(s);
                    progressBar.setMaximum(task.getDifferentSigners());
                    progressBar.setValue(task.getStatus());

                }
                if (task.isDone()) {
                    String st = task.getCRLerror();

                    timer.stop();
                    if (st.length() > 0) {
                        // timer.stop();

                        JOptionPane.showMessageDialog(frame,
                                "C'è stato un errore nela verifica CRL.\n"
                                        + task.getCRLerror(),
                                "Errore verifica CRL",
                                JOptionPane.ERROR_MESSAGE);
                        frame.hide();
                        FreeSignerSignApplet nuovo = new FreeSignerSignApplet();

                    }

                    frame.hide();
                    /*FreesignerVerifyFrame3 nuovo = new FreesignerVerifyFrame3(
                            task);*/

                }

            }
        });
        // *********************************

        panel4 = new JPanel();
        label2 = new JLabel();
        textPane1 = new JTextPane();
        panel5 = new JPanel();
        textArea1 = new JTextArea();
        textArea2 = new JTextArea();
        progressBar = new JProgressBar();
        progressBar.setValue(0);
        textPane2 = new JTextPane();
        textField1 = new JTextField();
        button1 = new JButton();
        panel6 = new JPanel();
        button2 = new JButton();
        button3 = new JButton();
        button4 = new JButton();
        GridBagConstraints gbc;
        // ======== this ========
        Container contentPane = getContentPane();
        contentPane.setLayout(new GridBagLayout());
        ((GridBagLayout) contentPane.getLayout()).columnWidths = new int[] {
                165, 0, 0 };
        ((GridBagLayout) contentPane.getLayout()).rowHeights = new int[] { 105,
                50, 0 };
        ((GridBagLayout) contentPane.getLayout()).columnWeights = new double[] {
                0.0, 1.0, 1.0E-4 };
        ((GridBagLayout) contentPane.getLayout()).rowWeights = new double[] {
                1.0, 0.0, 1.0E-4 };

        // ======== panel4 ========
        {
            panel4.setBackground(Color.white);
            panel4.setLayout(new GridBagLayout());
            ((GridBagLayout) panel4.getLayout()).columnWidths = new int[] {
                    160, 0 };
            ((GridBagLayout) panel4.getLayout()).rowHeights = new int[] { 0, 0,
                    0 };
            ((GridBagLayout) panel4.getLayout()).columnWeights = new double[] {
                    0.0, 1.0E-4 };
            ((GridBagLayout) panel4.getLayout()).rowWeights = new double[] {
                    1.0, 1.0, 1.0E-4 };

            // ---- label2 ----
            label2.setIcon(new ImageIcon("images"
                    + System.getProperty("file.separator")
                    + "logo-freesigner-piccolo.png"));
            gbc = new GridBagConstraints();
            gbc.gridx = 0;
            gbc.gridy = 0;
            gbc.fill = GridBagConstraints.HORIZONTAL;
            gbc.insets.bottom = 5;
            panel4.add(label2, gbc);

            // ---- textPane1 ----
            textPane1.setFont(new Font("Verdana", Font.BOLD, 12));
            textPane1.setText("Lettura\nbusta\ncrittografica");
            textPane1.setEditable(false);
            gbc = new GridBagConstraints();
            gbc.gridx = 0;
            gbc.gridy = 1;
            gbc.anchor = GridBagConstraints.NORTHWEST;
            panel4.add(textPane1, gbc);
        }
        gbc = new GridBagConstraints();
        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.fill = GridBagConstraints.BOTH;
        gbc.insets.bottom = 5;
        gbc.insets.right = 5;
        contentPane.add(panel4, gbc);

        // ======== panel5 ========
        {
            panel5.setBackground(Color.white);
            panel5.setLayout(new GridBagLayout());
            ((GridBagLayout) panel5.getLayout()).columnWidths = new int[] { 0,
                    205, 0, 0 };
            ((GridBagLayout) panel5.getLayout()).rowHeights = new int[] { 100,
                    0, 30, 30, 0 };
            ((GridBagLayout) panel5.getLayout()).columnWeights = new double[] {
                    1.0, 0.0, 1.0, 1.0E-4 };
            ((GridBagLayout) panel5.getLayout()).rowWeights = new double[] {
                    0.0, 0.0, 1.0, 1.0, 1.0E-4 };

            // ---- textArea1 ----
            textArea1.setFont(new Font("Verdana", Font.BOLD, 14));
            textArea1.setText("Lettura busta crittografica");
            textArea1.setEditable(false);
            gbc = new GridBagConstraints();
            gbc.gridx = 0;
            gbc.gridy = 0;
            gbc.gridwidth = 3;
            gbc.fill = GridBagConstraints.VERTICAL;
            gbc.insets.bottom = 5;
            panel5.add(textArea1, gbc);

            // ---- textArea2 ----
            textArea2.setFont(new Font("Verdana", Font.PLAIN, 12));
            textArea2.setText("Inizializzazione\n");
            textArea2.setColumns(30);
            gbc = new GridBagConstraints();
            gbc.gridx = 0;
            gbc.gridy = 1;
            gbc.gridwidth = 3;
            gbc.fill = GridBagConstraints.BOTH;
            panel5.add(textArea2, gbc);

            progressBar.setValue(0);
            progressBar.setStringPainted(true);
            progressBar.setBounds(0, 0, 300, 150);

            gbc = new GridBagConstraints();
            gbc.gridx = 0;
            gbc.gridy = 2;
            gbc.fill = GridBagConstraints.HORIZONTAL;
            gbc.insets.bottom = 5;
            gbc.insets.right = 5;
            gbc.gridwidth = 3;
            panel5.add(progressBar, gbc);

        }
        gbc = new GridBagConstraints();
        gbc.gridx = 1;
        gbc.gridy = 0;
        gbc.fill = GridBagConstraints.BOTH;
        gbc.insets.bottom = 5;
        contentPane.add(panel5, gbc);

        // ======== panel6 ========
        {
            panel6.setBackground(Color.white);
            panel6.setLayout(new GridBagLayout());
            ((GridBagLayout) panel6.getLayout()).columnWidths = new int[] { 0,
                    0, 0, 0 };
            ((GridBagLayout) panel6.getLayout()).rowHeights = new int[] { 0, 0 };
            ((GridBagLayout) panel6.getLayout()).columnWeights = new double[] {
                    1.0, 1.0, 1.0, 1.0E-4 };
            ((GridBagLayout) panel6.getLayout()).rowWeights = new double[] {
                    1.0, 1.0E-4 };

            // ---- button2 ----
            button2.setText("Indietro");
            gbc = new GridBagConstraints();
            gbc.gridx = 0;
            gbc.gridy = 0;
            gbc.insets.right = 5;
            button2.addActionListener(new ActionListener() {
                public void actionPerformed(ActionEvent e) {

                    frame.hide();

                    FreeSignerSignApplet nuovo = new FreeSignerSignApplet();

                }
            });

            // panel6.add(button2, gbc);

            // ---- button4 ----
            button4.setText("Annulla");
            gbc = new GridBagConstraints();
            gbc.gridx = 2;
            gbc.gridy = 0;
            // panel6.add(button4, gbc);
        }
        gbc = new GridBagConstraints();
        gbc.gridx = 1;
        gbc.gridy = 1;
        gbc.fill = GridBagConstraints.BOTH;
        contentPane.add(panel6, gbc);
        contentPane.setBackground(Color.white);
        frame.setContentPane(contentPane);
        frame.setTitle("Freesigner");
        frame.setSize(300, 150);
        frame.setResizable(false);
        frame.pack();
        Dimension d = Toolkit.getDefaultToolkit().getScreenSize();
        frame.setLocation((d.width - frame.getWidth()) / 2, (d.height - frame
                .getHeight()) / 2);

        frame.show();

        frame.setVisible(true);

        frame.addWindowListener(new WindowAdapter() {
            public void windowClosing(WindowEvent e) {
                System.exit(0);
            }
        });

    }

    void setMessage(String s) {
        textField1.setText(s);
    }

    private Timer timer;

    private JProgressBar progressBar;

    private VerifyTask task;

    private String fileDaAprire;

    private JFrame frame;

    private JFrame frameprec;

    private JPanel panel4;

    private JLabel label2;

    private JTextPane textPane1;

    private JPanel panel5;

    private JTextArea textArea1;

    private JTextArea textArea2;

    private JTextPane textPane2;

    private JTextField textField1;

    private JButton button1;

    private JPanel panel6;

    private JButton button2;

    private JButton button3;

    private JButton button4;

}
