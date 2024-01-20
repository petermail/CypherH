using CypherH;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Security.Cryptography;

namespace UnitTestProject1
{
    [TestClass]
    public class CypherTest
    {
        [TestMethod]
        public void Cypher_Simple()
        {
            var cypher = new Cypher();
            var text = "This is little longer text with some special characters like: @#$%. Is it all ok? What about this: ö";

            var encoded = cypher.Encode(text, "password");
            var decoded = cypher.Decode(encoded, "password");

            Assert.AreNotEqual(text, encoded);
            Assert.AreEqual(text, decoded);
        }

        [TestMethod]
        public void Cypher_WithInitVect()
        {
            var cypher = new Cypher();
            var text = "This is little longer text with some special characters like: @#$%. Is it all ok? What about this: ö";
            var initVect = InitVector.Create();

            var encoded = cypher.Encode(text, "password 2", initVect);
            var decoded = cypher.Decode(encoded, "password 2", initVect);

            Assert.AreNotEqual(text, encoded);
            Assert.AreEqual(text, decoded);
        }

        [TestMethod]
        public void Cypher_WithInitVectAndKey()
        {
            var cypher = new Cypher();
            var text = "This is little longer text with some special characters like: @#$%. Is it all ok? What about this: ö";
            var initVect = InitVector.Create();
            var salt = Cypher.GenerateRandomCryptographicKey(256);
            var key = cypher.GetKey("LongerPassword@WithSpecialChar?", salt, 1000);

            var encoded = cypher.Encode(text, key, initVect);
            var decoded = cypher.Decode(encoded, key, initVect);

            Assert.AreNotEqual(text, encoded);
            Assert.AreEqual(text, decoded);
        }

        [TestMethod]
        public void Cypher_WithInitVectAndKey2()
        {
            var cypher = new Cypher();
            var text = "This is little longer text with some special characters like: @#$%. Is it all ok? What about this: ö";
            var initVect = InitVector.Create();
            var salt = Cypher.GenerateRandomCryptographicKey(16);
            var key = cypher.GetKey("LongerPassword@WithSpecialChar?", salt, 1000);

            var encoded = cypher.Encode(text, key, initVect);
            var decoded = cypher.Decode(encoded, key, initVect);

            Assert.AreNotEqual(text, encoded);
            Assert.AreEqual(text, decoded);
        }

        [TestMethod]
        public void Cypher_WithKey()
        {
            var cypher = new Cypher();
            var text = "This is little longer text with some special characters like: @#$%. Is it all ok? What about this: ö";
            var salt = Cypher.GenerateRandomCryptographicKey(256);
            var key = cypher.GetKey("LongerPassword@WithSpecialChar?", salt, 1000);

            var encoded = cypher.Encode(text, key);
            var decoded = cypher.Decode(encoded, key);

            Assert.AreNotEqual(text, encoded);
            Assert.AreEqual(text, decoded);
        }

        [TestMethod]
        public void Cypher_WrongPassword()
        {
            var cypher = new Cypher();
            var text = "This is little longer text with some special characters like: @#$%. Is it all ok? What about this: ö";

            var encoded = cypher.Encode(text, "password");
            var action = new System.Action(() => cypher.Decode(encoded, "passwOrd"));
            Assert.ThrowsException<CryptographicException>(action);

            var decoded = cypher.Decode(encoded, "password");

            Assert.AreEqual(text, decoded);
        }
    }
}
