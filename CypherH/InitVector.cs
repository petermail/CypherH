using System;
using System.Collections.Generic;
using System.Text;

namespace CypherH
{
    public class InitVector
    {
        public byte[] Value { get; set; }

        public static InitVector Create()
        {
            return new InitVector() { Value = Cypher.GenerateRandomCryptographicKey(16) };
        }
    }
}
