using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace AESEncryptionDecryption
{
    public class AESEncryptionDecryption
    {

        public static string Encrypt(string plainText , string key)
        {
            byte[] iv = new byte[16];
            byte[] array;

            using (Aes aes = Aes.Create())
            {
                aes.Key = Encoding.UTF8.GetBytes(key);
                aes.IV = iv;

                ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV);

                using (MemoryStream memoryStream = new MemoryStream())
                {
                    using (CryptoStream cryptoStream = new CryptoStream((Stream)memoryStream, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter streamWriter = new StreamWriter((Stream)cryptoStream))
                        {
                            streamWriter.Write(plainText);
                        }

                        array = memoryStream.ToArray();
                    }
                }
            }

            return Convert.ToBase64String(array);
        }

        public static string Decrypt(string cipherText, string key)
        {
            byte[] iv = new byte[16];
            byte[] buffer = Convert.FromBase64String(cipherText);

            using (Aes aes = Aes.Create())
            {
                aes.Key = Encoding.UTF8.GetBytes(key);
                aes.IV = iv;
                ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV);

                using (MemoryStream memoryStream = new MemoryStream(buffer))
                {
                    using (CryptoStream cryptoStream = new CryptoStream((Stream)memoryStream, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader streamReader = new StreamReader((Stream)cryptoStream))
                        {
                            return streamReader.ReadToEnd();
                        }
                    }
                }
            }
        }

        //public static string Encrypt(string InputText, string KeyString)
        //{

        //    MemoryStream memoryStream = null;
        //    CryptoStream cryptoStream = null;
        //    try
        //    {
        //        using (RijndaelManaged AES = new RijndaelManaged())
        //        {
        //            AES.KeySize = 256;
        //            AES.BlockSize = 128;
        //            AES.Padding = PaddingMode.Zeros;
        //            AES.Mode = CipherMode.CBC;
        //            byte[] PlainText = System.Text.Encoding.Unicode.GetBytes(InputText);

        //            PasswordDeriveBytes SecretKey = new PasswordDeriveBytes(KeyString, Encoding.ASCII.GetBytes(KeyString.Length.ToString()));
        //            using (ICryptoTransform Encryptor = AES.CreateEncryptor(SecretKey.GetBytes(16), SecretKey.GetBytes(16)))
        //            {
        //                using (memoryStream = new MemoryStream())
        //                {
        //                    using (cryptoStream = new CryptoStream(memoryStream, Encryptor, CryptoStreamMode.Write))
        //                    {
        //                        cryptoStream.Write(PlainText, 0, PlainText.Length);
        //                        cryptoStream.FlushFinalBlock();
        //                        return Convert.ToBase64String(memoryStream.ToArray());
        //                    }
        //                }
        //            }
        //        }

        //    }
        //    catch
        //    {
        //        throw;
        //    }
        //    finally
        //    {
        //        if (memoryStream != null)
        //            memoryStream.Close();
        //        if (cryptoStream != null)
        //            cryptoStream.Close();
        //    }
        //}

        //static string DecryptStringFromBytes(byte[] cipherText, byte[] Key, byte[] IV)
        //{
        //    // Check arguments. 
        //    if (cipherText == null || cipherText.Length <= 0)
        //        throw new ArgumentNullException("cipherText");
        //    if (Key == null || Key.Length <= 0)
        //        throw new ArgumentNullException("Key");
        //    if (IV == null || IV.Length <= 0)
        //        throw new ArgumentNullException("Key");

        //    // Declare the string used to hold 
        //    // the decrypted text. 
        //    string plaintext = null;

        //    // Create an RijndaelManaged object 
        //    // with the specified key and IV. 
        //    using (var cipher = new RijndaelManaged())
        //    {
        //        cipher.Key = Key;
        //        cipher.IV = IV;
        //        //cipher.Mode = CipherMode.CBC;
        //        //cipher.Padding = PaddingMode.PKCS7;

        //        // Create a decrytor to perform the stream transform.
        //        ICryptoTransform decryptor = cipher.CreateDecryptor(cipher.Key, cipher.IV);

        //        // Create the streams used for decryption. 
        //        using (MemoryStream msDecrypt = new MemoryStream(cipherText))
        //        {
        //            using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
        //            {
        //                using (StreamReader srDecrypt = new StreamReader(csDecrypt))
        //                {
        //                    // Read the decrypted bytes from the decrypting stream 
        //                    // and place them in a string.
        //                    plaintext = srDecrypt.ReadToEnd();
        //                }
        //            }
        //        }
        //    }

        //    return plaintext;
        //}

        //public static string Decrypt(string InputText, string KeyString)
        //{
        //    MemoryStream memoryStream = null;
        //    CryptoStream cryptoStream = null;
        //    try
        //    {
        //        byte[] key = Encoding.UTF8.GetBytes(KeyString);
        //        byte[] iv = Encoding.UTF8.GetBytes(KeyString);
        //        try
        //        {
        //            using (var rijndaelManaged =
        //                   new RijndaelManaged { Key = key, Mode = CipherMode.CBC })
        //            using ( memoryStream =
        //                   new MemoryStream(Convert.FromBase64String(InputText)))
        //            using ( cryptoStream =
        //                   new CryptoStream(memoryStream,
        //                       rijndaelManaged.CreateDecryptor(key, iv),
        //                       CryptoStreamMode.Read))
        //            {
        //                return new StreamReader(cryptoStream).ReadToEnd();
        //            }
        //        }
        //        catch (CryptographicException e)
        //        {
        //            Console.WriteLine("A Cryptographic error occurred: {0}", e.Message);
        //            return null;
        //        }
        //        // You may want to catch more exceptions here...

        //        //using (RijndaelManaged AES = new RijndaelManaged())
        //        //{
        //        //    AES.BlockSize = 128;
        //        //    AES.KeySize = 256;
        //        //    AES.Key = Encoding.UTF8.GetBytes(KeyString);
        //        //    AES.Padding = PaddingMode.Zeros;
        //        //    AES.Mode = CipherMode.CBC;
        //        //    byte[] EncryptedData = Convert.FromBase64String(InputText);
        //        //    PasswordDeriveBytes SecretKey = new PasswordDeriveBytes(KeyString, Encoding.ASCII.GetBytes(KeyString.Length.ToString()));
        //        //    using (ICryptoTransform Decryptor = AES.CreateDecryptor(SecretKey.GetBytes(16), SecretKey.GetBytes(16)))
        //        //    {
        //        //        using (memoryStream = new MemoryStream(EncryptedData))
        //        //        {
        //        //            using (cryptoStream = new CryptoStream(memoryStream, Decryptor, CryptoStreamMode.Read))
        //        //            {
        //        //                byte[] PlainText = new byte[EncryptedData.Length];
        //        //                var base64data =  Encoding.Unicode.GetString(PlainText, 0, cryptoStream.Read(PlainText, 0, PlainText.Length));
        //        //                return "";
        //        //            }
        //        //        }
        //        //    }
        //        //}

        //    }
        //    catch
        //    {
        //        throw;
        //    }
        //    finally
        //    {
        //        if (memoryStream != null)
        //            memoryStream.Close();
        //        if (cryptoStream != null)
        //            cryptoStream.Close();
        //    }
        //}


    }
}