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

import javax.swing.*;

/**
 * PIN GUI
 *
 * @author Francesco Cendron
 */



class PINDialog extends JDialog implements ActionListener {


    private JPasswordField password = new JPasswordField("");

    private boolean okPressed;

    private JButton okButton;

    private JButton cancelButton;

    public PINDialog(JFrame parent) {
        super(parent, "PIN", true);
        this.setSize(200, 50);
        GridBagConstraints gbc = new GridBagConstraints();
        Container contentPane = getContentPane();
        contentPane.setLayout(new GridBagLayout());
        Dimension d = Toolkit.getDefaultToolkit().getScreenSize();
        this.setLocation((d.width - this.getWidth()) / 2, (d.height - this
                .getHeight()) / 2);

        JPanel p1 = new JPanel(new GridLayout(2, 2, 3, 3));
        gbc.gridx = 0;
        gbc.gridy = 0;

        p1.add(new JLabel("Inserire il PIN:"), gbc);
        password.setSize(8, 1);
        password.addActionListener(this);
        p1.add(password);
        gbc = new GridBagConstraints();
        gbc.gridx = 0;
        gbc.gridy = 1;
        gbc.anchor = GridBagConstraints.WEST;
        gbc.fill = GridBagConstraints.BOTH;
        gbc.insets.bottom = 1;
        gbc.insets.right = 5;

        contentPane.add(p1, gbc);

        Panel p2 = new Panel();
        okButton = addButton(p2, "OK");
        cancelButton = addButton(p2, "Cancel");
        gbc = new GridBagConstraints();
        gbc.gridx = 0;
        gbc.gridy = 2;
        gbc.anchor = GridBagConstraints.WEST;
        gbc.fill = GridBagConstraints.VERTICAL;
        gbc.insets.bottom = 1;
        gbc.insets.right = 5;

        contentPane.add(p2, gbc);
        setSize(200, 120);
    }

    private JButton addButton(Container c, String name) {
        JButton button = new JButton(name);
        button.addActionListener(this);
        c.add(button);
        return button;
    }

    public void actionPerformed(ActionEvent evt) {
        Object source = evt.getSource();
        if ((source == okButton) || (source == password)) {
            okPressed = true;
            setVisible(false);
        } else if (source == cancelButton) {
            setVisible(false);

        }

    }

    public boolean showDialog(UserInfo transfer) {

        password.setText(transfer.password);

        okPressed = false;
        show();
        if (okPressed) {
            transfer.password = new String(password.getPassword());
        }

        return okPressed;
    }
}

/**
 * Convenience object for PINDialog
 * Classe per la gestione della richiesta PIN
 *
 * @author Francesco Cendron
 */
class UserInfo {


    public String password;

    public UserInfo(String p) {

        password = p;
    }
}

