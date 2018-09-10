using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace Encryption.Asymmetric
{
    public class RSAKeyPair : IKeyPair, IDisposable
    {
        public int KeySize { get; private set; } = 512;

        public byte[] PrivateKey { get; private set; }
        public byte[] PublicKey { get; private set; }

        protected RSAParameters RSAParams
        {
            get
            {
                RSAParameters result = new RSAParameters();

                IEnumerable<byte> pk = this.PrivateKey.AsEnumerable();

                int eighth = KeySize / 8,
                    sixteenth = KeySize / 16;

                result.Modulus = pk.Take(eighth).ToArray();
                pk = pk.Skip(eighth);

                result.Exponent = pk.Take(3).ToArray();
                pk = pk.Skip(3);

                result.P = pk.Take(sixteenth).ToArray();
                pk = pk.Skip(sixteenth);

                result.Q = pk.Take(sixteenth).ToArray();
                pk = pk.Skip(sixteenth);

                result.DP = pk.Take(sixteenth).ToArray();
                pk = pk.Skip(sixteenth);

                result.DQ = pk.Take(sixteenth).ToArray();
                pk = pk.Skip(sixteenth);

                result.InverseQ = pk.Take(sixteenth).ToArray();
                pk = pk.Skip(sixteenth);

                result.D = pk.Take(eighth).ToArray();
                pk = pk.Skip(eighth);

                return result;
            }
        }

        private RSACryptoServiceProvider _rsa;
        private RSACryptoServiceProvider RSA
        {
            get
            {
                if (this._rsa == null)
                    this._rsa = new RSACryptoServiceProvider(KeySize);

                return this._rsa;
            }
        }

        public string Mnemonic => throw new NotImplementedException();

        public RSAKeyPair()
        {
            RSAParameters paras = this.RSA.ExportParameters(true);

            // PublicKey Segments
            // Modulas = [KeySize / 8] Exponent = [3]
            this.PublicKey = paras.Modulus.Concat(paras.Exponent).ToArray();

            // PrivateKey Segments
            this.PrivateKey = this.PublicKey
                .Concat(paras.P) // [KeySize / 16]
                .Concat(paras.Q) // [KeySize / 16]
                .Concat(paras.DP) // [KeySize / 16]
                .Concat(paras.DQ) // [KeySize / 16]
                .Concat(paras.InverseQ) // [KeySize / 16]
                .Concat(paras.D) // [KeySize / 8]
                .ToArray();
        }

        public RSAKeyPair(byte[] privateKey)
        {
            this.PrivateKey = privateKey;
            this.PublicKey = this.PrivateKey.Take(KeySize / 8 + 3).ToArray();

            this.RSA.ImportParameters(this.RSAParams);
        }

        public byte[] Encrypt(string payload, Encoding encoding = null)
        {
            if (encoding == null)
                encoding = Encoding.UTF8;

            return this.Encrypt(Encoding.UTF8.GetBytes(payload));
        }

        public byte[] Encrypt(byte[] payload)
        {
            return this.RSA.Encrypt(payload, false);
        }

        public string Decrypt(byte[] payload, Encoding encoding)
        {
            if (encoding == null)
                encoding = Encoding.UTF8;

            byte[] payloadDecrypt = this.Decrypt(payload);

            return encoding.GetString(payloadDecrypt);
        }

        public byte[] Decrypt(byte[] payload)
        {
            return this.RSA.Decrypt(payload, false);
        }

        public void Dispose()
        {
            if (this._rsa != null)
                this._rsa.Dispose();
        }
    }
}
