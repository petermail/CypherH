using System;
using System.Collections.Generic;
using System.Security;
using System.Text;

namespace CypherH
{
    public class Password
    {
        public byte[] ByteVersion { get; }

        public Password(string password)
        {
            ByteVersion = Encoding.UTF8.GetBytes(password);
        }

        public Password(byte[] password)
        {
            ByteVersion = password;
        }
    }
}
