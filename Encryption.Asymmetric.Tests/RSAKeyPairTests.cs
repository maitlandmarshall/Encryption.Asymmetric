using Microsoft.VisualStudio.TestTools.UnitTesting;
using Encryption.Asymmetric;
using System.Text;
using System.Security.Cryptography;

[TestClass]
public class RSAKeyPairTests
{
    [TestMethod]
    public void NewKeyPair()
    {
        using (RSAKeyPair kp = new RSAKeyPair())
        using (RSAKeyPair kp2 = new RSAKeyPair())
        {
            Assert.AreNotEqual(new byte[0], kp.PrivateKey);
            Assert.AreNotEqual(new byte[0], kp.PublicKey);

            CollectionAssert.AreNotEqual(kp2.PrivateKey, kp.PrivateKey);
            CollectionAssert.AreNotEqual(kp2.PublicKey, kp.PublicKey);
        }
    }

    [TestMethod]
    public void RestoreKeyPair()
    {
        using (RSAKeyPair original = new RSAKeyPair())
        using (RSAKeyPair restored = new RSAKeyPair(original.PrivateKey))
        {
            CollectionAssert.AreEqual(original.PrivateKey, restored.PrivateKey);
            CollectionAssert.AreEqual(original.PublicKey, restored.PublicKey);
        }
    }

    [TestMethod]
    public void Encrypt()
    {
        using (RSAKeyPair kp = new RSAKeyPair())
        {
            string data = "Hello my name is Maitland";
            byte[] dataEncrypted = kp.Encrypt(data, Encoding.UTF8);
            string dataConvertedToUTF8 = Encoding.UTF8.GetString(dataEncrypted);

            Assert.AreNotEqual(data, dataConvertedToUTF8);
        }
    }

    [TestMethod]
    public void Decrypt()
    {
        using (RSAKeyPair kp = new RSAKeyPair())
        using (RSAKeyPair kp2 = new RSAKeyPair())
        {
            string data = "Hello I am Maitland I make code";

            byte[] dataEncrypted = kp.Encrypt(data, Encoding.UTF8);
            string dataDecrypted = kp.Decrypt(dataEncrypted, Encoding.UTF8);

            Assert.AreEqual(data, dataDecrypted);
            Assert.ThrowsException<CryptographicException>(() =>
            {
                kp2.Decrypt(dataEncrypted, Encoding.UTF8);
            });
        }
    }

        
}

