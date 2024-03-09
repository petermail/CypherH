using EncryptionSafe.Encryption;
using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace CypherH
{
    public class Cypher
    {
        public byte[] SaltValue { get; set; }
        public InitVector InitVector { get; set; }
        public int PasswordIterations { get; set; }

        private const int _keySize = 256;

        public Cypher()
        {
            SaltValue = GenerateRandomCryptographicKey(64);
            InitVector = InitVector.Create();
            PasswordIterations = 100000;
        }

        public string Encode(string text, Password password, InitVector initVector = null)
        {
            var key = GetKey(password, SaltValue, PasswordIterations);
            return RijndaelAlgorithm.EncryptAes(text, initVector?.Value ?? InitVector.Value, key);
        }
        public string Encode(string text, byte[] key, InitVector initVector = null)
        {
            return RijndaelAlgorithm.EncryptAes(text, initVector?.Value ?? InitVector.Value, key);
        }

        public string Decode(string text, Password password, InitVector initVector = null)
        {
            var key = GetKey(password, SaltValue, PasswordIterations);
            return RijndaelAlgorithm.DecryptAes(text, initVector?.Value ?? InitVector.Value, key);
        }
        public string Decode(string text, byte[] key, InitVector initVector = null)
        {
            return RijndaelAlgorithm.DecryptAes(text, initVector?.Value ?? InitVector.Value, key);
        }

        public byte[] GetKey(Password password, byte[] saltValue = null, int? passwordIterations = null)
        {
            return RijndaelAlgorithm.GetKeyInBytes(password.ByteVersion, saltValue ?? SaltValue, passwordIterations ?? PasswordIterations, _keySize);
        }

        public static byte[] GenerateRandomCryptographicKey(int keyLength)
        {
            RNGCryptoServiceProvider rngCryptoServiceProvider = new RNGCryptoServiceProvider();
            byte[] randomBytes = new byte[keyLength];
            rngCryptoServiceProvider.GetBytes(randomBytes);
            return randomBytes;
        }

        public static byte[] Hash(string text)
        {
            using (var sha256 = SHA256.Create())
            {
                return sha256.ComputeHash(Convert.FromBase64String(text));
            }
        }
    }

    public static class StaticCypher
    {
        public static string ToBase64String(this byte[] bytes)
        {
            return Convert.ToBase64String(bytes);
        }
    }
}
