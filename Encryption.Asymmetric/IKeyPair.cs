using System;
using System.Collections.Generic;
using System.Text;

namespace Encryption.Asymmetric
{
    interface IKeyPair
    {
        byte[] PrivateKey { get; }
        byte[] PublicKey { get; }

        string Mnemonic { get; }

        byte[] Encrypt(string payload, Encoding encoding = null);
        byte[] Encrypt(byte[] payload);

        string Decrypt(byte[] payload, Encoding encoding);
        byte[] Decrypt(byte[] payload);
    }
}
