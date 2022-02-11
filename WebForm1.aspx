<%@ Page Language="C#" AutoEventWireup="true" CodeBehind="WebForm1.aspx.cs" Inherits="AESEncryptionDecryption.WebForm1" %>

<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head runat="server">
    <title></title>
</head>
<body>
    <form id="form1" runat="server">
    <div>
        <table>
            <tr>
                <td>
                    Input
                </td>
                <td>
                    <asp:TextBox ID="txtInput" runat="server" Width="350"></asp:TextBox>
                </td>
                <td>
                    <asp:Button ID="btnEncrypt" runat="server" Text="Encrypt" OnClick="btnEncrypt_Click" />
                </td>
            </tr>
            <tr>
                <td>
                    Encrypted String
                </td>
                <td>
                    <asp:TextBox ID="txtEncryptedString" runat="server" Width="350"></asp:TextBox>
                </td>
                <td>
                    <asp:Button ID="btnDecrypt" runat="server" Text="Decrypt" OnClick="btnDecrypt_Click" />
                </td>
            </tr>
            <tr>
                <td>
                    Decrypted Output
                </td>
                <td>
                    <asp:TextBox ID="txtDecryptedString" runat="server" Width="350"></asp:TextBox>
                </td>
            </tr>
        </table>
    </div>
    </form>
</body>
</html>
