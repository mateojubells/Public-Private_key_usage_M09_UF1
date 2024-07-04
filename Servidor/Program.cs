using System;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;

class Receptor
{
    static void Main()
    {
        try
        {
            TcpListener server = new TcpListener(IPAddress.Parse("127.0.0.1"), 5000);
            server.Start();
            Console.WriteLine("Servidor iniciado y esperando conexiones...");

            TcpClient client = server.AcceptTcpClient();
            NetworkStream stream = client.GetStream();
            Console.WriteLine("Conexión aceptada del emisor.");

            RSAParameters RSAKeyInfo;
            byte[] publicKey;
            using (RSACryptoServiceProvider RSA = new RSACryptoServiceProvider())
            {
                RSAKeyInfo = RSA.ExportParameters(true);
                publicKey = RSA.ExportCspBlob(false);
                Console.WriteLine("Claves RSA generadas.");
            }

            stream.Write(publicKey, 0, publicKey.Length);
            Console.WriteLine("Clave pública enviada al emisor.");

            byte[] encryptedMessage = new byte[1024];
            int bytesRead = stream.Read(encryptedMessage, 0, encryptedMessage.Length);
            byte[] dataToDecrypt = new byte[bytesRead];
            Array.Copy(encryptedMessage, dataToDecrypt, bytesRead);
            Console.WriteLine("Mensaje cifrado recibido.");

            byte[] decryptedData = RSADecrypt(dataToDecrypt, RSAKeyInfo, false);
            UnicodeEncoding ByteConverter = new UnicodeEncoding();
            string decryptedMessage = ByteConverter.GetString(decryptedData);
            Console.WriteLine("Mensaje descifrado: " + decryptedMessage);

            stream.Close();
            client.Close();
            server.Stop();
            Console.WriteLine("Conexión cerrada y servidor detenido.");
        }
        catch (Exception e)
        {
            Console.WriteLine("Error: " + e.Message);
        }
    }

    public static byte[] RSADecrypt(byte[] DataToDecrypt, RSAParameters RSAKeyInfo, bool DoOAEPPadding)
    {
        try
        {
            byte[] decryptedData;
            using (RSACryptoServiceProvider RSA = new RSACryptoServiceProvider())
            {
                RSA.ImportParameters(RSAKeyInfo);
                decryptedData = RSA.Decrypt(DataToDecrypt, DoOAEPPadding);
            }
            return decryptedData;
        }
        catch (CryptographicException e)
        {
            Console.WriteLine("Error al descifrar: " + e.ToString());
            return null;
        }
    }
}
