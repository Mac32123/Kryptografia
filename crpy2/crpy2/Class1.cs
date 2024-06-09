using System;
using System.Collections.Generic;
using System.Text;

namespace Cyberbezpieczenstwo
{
    class KeysJSON
    {
        public string privateKey { set; get; }
        public string publicKey { set; get; }
        public KeysJSON() {
        
        }
        public KeysJSON(string priv, string pub)
        {
            this.privateKey = priv;
            this.publicKey = pub;
        }
    }
}
