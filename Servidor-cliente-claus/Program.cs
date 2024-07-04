using System;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;

class Emisor
{
    static void Main()
    {
        try
        {
            TcpClient client = new TcpClient("127.0.0.1", 5000);
            NetworkStream stream = client.GetStream();
            Console.WriteLine("Conectado al servidor.");

            Console.WriteLine("Introduce un mensaje para enviar:");
            string message = Console.ReadLine();
            UnicodeEncoding ByteConverter = new UnicodeEncoding();
            byte[] dataToEncrypt = ByteConverter.GetBytes(message);

            byte[] publicKeyBuffer = new byte[1024];
            int bytesRead = stream.Read(publicKeyBuffer, 0, publicKeyBuffer.Length);
            byte[] publicKey = new byte[bytesRead];
            Array.Copy(publicKeyBuffer, publicKey, bytesRead);
            Console.WriteLine("Clave pública recibida del receptor.");

            RSAParameters RSAKeyInfo;
            using (RSACryptoServiceProvider RSA = new RSACryptoServiceProvider())
            {
                RSA.ImportCspBlob(publicKey);
                RSAKeyInfo = RSA.ExportParameters(false);
                Console.WriteLine("Clave pública importada.");
            }

            byte[] encryptedData = RSAEncrypt(dataToEncrypt, RSAKeyInfo, false);
            Console.WriteLine("Mensaje cifrado.");

            stream.Write(encryptedData, 0, encryptedData.Length);
            Console.WriteLine("Mensaje cifrado enviado al receptor.");

            stream.Close();
            client.Close();
            Console.WriteLine("Conexión cerrada.");
        }
        catch (Exception e)
        {
            Console.WriteLine("Error: " + e.Message);
        }
    }

    public static byte[] RSAEncrypt(byte[] DataToEncrypt, RSAParameters RSAKeyInfo, bool DoOAEPPadding)
    {
        try
        {
            byte[] encryptedData;
            using (RSACryptoServiceProvider RSA = new RSACryptoServiceProvider())
            {
                RSA.ImportParameters(RSAKeyInfo);
                encryptedData = RSA.Encrypt(DataToEncrypt, DoOAEPPadding);
            }
            return encryptedData;
        }
        catch (CryptographicException e)
        {
            Console.WriteLine("Error al cifrar: " + e.Message);
            return null;
        }
    }
}
