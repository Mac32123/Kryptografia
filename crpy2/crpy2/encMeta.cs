using System;
using System.Collections.Generic;
using System.Text;

namespace Cyberbezpieczenstwo
{
    class encMeta
    {
        public string mode { set; get; }
        public string alg { set; get; }
        public string encKey { set; get; }
        public encMeta() {

        }
        public encMeta(string mode, string alg, string encKey)
        {
            this.mode = mode;
            this.alg = alg;
            this.encKey = encKey;
        }
    }
}
