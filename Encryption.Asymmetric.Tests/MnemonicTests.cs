
using Encryption.Asymmetric;
using Microsoft.VisualStudio.TestTools.UnitTesting;


[TestClass]
public class MnemonicTests
{
    [TestMethod]
    public void EncodeRSA()
    {
        RSAKeyPair kp = new RSAKeyPair();
        string mneomnic = Mnemonic.Encode(kp.PrivateKey);

        Assert.IsTrue(mneomnic.Length > 0);

        RSAKeyPair kp2 = new RSAKeyPair();
        string mnemonic2 = Mnemonic.Encode(kp2.PrivateKey);

        Assert.AreNotEqual(mneomnic, mnemonic2);
    }

    [TestMethod]
    public void DecodeRSA()
    {
        for (int i = 0; i < 100; i++)
        {
            RSAKeyPair kp = new RSAKeyPair(512);

            string mneomnic = Mnemonic.Encode(kp.PrivateKey);
            byte[] privateKey1 = Mnemonic.Decode(mneomnic);

            CollectionAssert.AreEqual(kp.PrivateKey, privateKey1);
        }
    }
}

