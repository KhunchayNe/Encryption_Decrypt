using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.UI;
using System.Web.UI.WebControls;

namespace AESEncryptionDecryption
{
    public partial class WebForm1 : System.Web.UI.Page
    {
        string AESKey = "20d135f0f28185b84a4cf7aa51f29500";
        protected void Page_Load(object sender, EventArgs e)
        {

        }

        protected void btnEncrypt_Click(object sender, EventArgs e)
        {
            txtEncryptedString.Text = AESEncryptionDecryption.Encrypt(txtInput.Text, AESKey);
        }

        protected void btnDecrypt_Click(object sender, EventArgs e)
        {
            txtDecryptedString.Text = AESEncryptionDecryption.Decrypt(txtEncryptedString.Text, AESKey);
        }
    }
}