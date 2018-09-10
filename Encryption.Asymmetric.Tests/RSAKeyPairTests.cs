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
        RSAKeyPair kp = new RSAKeyPair();

        Assert.AreNotEqual(new byte[0], kp.PrivateKey);
        Assert.AreNotEqual(new byte[0], kp.PublicKey);

        RSAKeyPair kp2 = new RSAKeyPair();
        CollectionAssert.AreNotEqual(kp2.PrivateKey, kp.PrivateKey);
        CollectionAssert.AreNotEqual(kp2.PublicKey, kp.PublicKey);
    }

    [TestMethod]
    public void RestoreKeyPair()
    {
        RSAKeyPair original = new RSAKeyPair();
        RSAKeyPair restored = new RSAKeyPair(original.PrivateKey);

        CollectionAssert.AreEqual(original.PrivateKey, restored.PrivateKey);
        CollectionAssert.AreEqual(original.PublicKey, restored.PublicKey);
    }

    [TestMethod]
    public void Encrypt()
    {
        RSAKeyPair kp = new RSAKeyPair();

        string data = "Hello my name is Maitland";
        byte[] dataEncrypted = kp.Encrypt(data, Encoding.UTF8);
        string dataConvertedToUTF8 = Encoding.UTF8.GetString(dataEncrypted);

        Assert.AreNotEqual(data, dataConvertedToUTF8);
    }

    [TestMethod]
    public void Decrypt()
    {
        RSAKeyPair kp = new RSAKeyPair();

        string data = "Hello I am Maitland I make code";

        byte[] dataEncrypted = kp.Encrypt(data, Encoding.UTF8);
        string dataDecrypted = kp.Decrypt(dataEncrypted, Encoding.UTF8);

        Assert.AreEqual(data, dataDecrypted);

        RSAKeyPair kp2 = new RSAKeyPair();
        Assert.ThrowsException<CryptographicException>(() =>
        {
            kp2.Decrypt(dataEncrypted, Encoding.UTF8);
        });
    }

        
}

