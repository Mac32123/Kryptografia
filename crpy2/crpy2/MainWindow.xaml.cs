using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Threading;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;
using System.Diagnostics;
using System.Net.Sockets;
using System.Net;
using System.Security.Cryptography;
using System.Windows.Forms;
using Cryptography;
using System.IO;
using System.Text.Json;
using System.Xml.Serialization;

namespace Cyberbezpieczenstwo
{
    /// <summary>
    /// Logika interakcji dla klasy MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        private Socket handler = null;
        private bool isConnected = false;
        private Dictionary<string, string> keys;
        string privKey = null;
        string pubKey = null;
        bool isServer = false;
        public MainWindow()
        {
            keys = new Dictionary<string, string>();
            InitializeComponent();
            string[] elements = { "cbc", "ecb"};
            foreach (var e in elements)
            {
                cb.Items.Add(e);
            }
            cb2.Items.Add("AES");
            cb2.Items.Add("DES");
        }

        //wysyłanie i szyfrowanie wiadomości tekstowej 
        private void InitKey(object sender, RoutedEventArgs e) {
            Cryptography.RSA.GenerateKeys(out var privateKey, out var publicKey, keySize: 2048);
            var stringReader = new StringReader(privateKey);
            var serializer = new XmlSerializer(typeof(RSAParameters));
            var deskey = (RSAParameters)serializer.Deserialize(stringReader);
            var privKeySys = System.Security.Cryptography.RSA.Create(deskey);
            var buffer = new StringBuilder();
            buffer.AppendLine("-----BEGIN RSA PRIVATE KEY-----");
            buffer.AppendLine(Convert.ToBase64String(privKeySys.ExportRSAPrivateKey(),
                Base64FormattingOptions.InsertLineBreaks));
            buffer.AppendLine("-----END RSA PRIVATE KEY-----");

            stringReader = new StringReader(publicKey);
            serializer = new XmlSerializer(typeof(RSAParameters));
            deskey = (RSAParameters)serializer.Deserialize(stringReader);
            var pubKeySys = System.Security.Cryptography.RSA.Create(deskey);
            var buffer1 = new StringBuilder();
            buffer1.AppendLine("-----BEGIN RSA PUBLIC KEY-----");
            buffer1.AppendLine(Convert.ToBase64String(pubKeySys.ExportRSAPublicKey(),
                Base64FormattingOptions.InsertLineBreaks));
            buffer1.AppendLine("-----END RSA PUBLIC KEY-----");


            FolderBrowserDialog fvd = new FolderBrowserDialog();
            var result = fvd.ShowDialog();
            if (result == System.Windows.Forms.DialogResult.Cancel) return;
            string folder = fvd.SelectedPath;
            StreamWriter writer = new StreamWriter(folder + "/priv.pem");
            writer.Write(buffer);
            writer.Close();
            writer = new StreamWriter(folder + "/pub.pem");
            writer.Write(buffer1);
            writer.Close();
            System.Windows.MessageBox.Show("Generated keys succesfully!");
        }

        private void readPrivKey(object sender, RoutedEventArgs e) {
            readKey("Private");
        }
        private void readPubKey(object sender, RoutedEventArgs e)
        {
            readKey("Public");
        }

        private void readKey(string keyType) {
            OpenFileDialog openFileDialog = new OpenFileDialog();
            openFileDialog.Filter = "Pem files (*.pem)|*.pem";
            var result = openFileDialog.ShowDialog();
            if (result == System.Windows.Forms.DialogResult.Cancel) return;
            var dfile = openFileDialog.FileName;
            StreamReader reader = new StreamReader(dfile);
            string header = reader.ReadLine();
            if (keyType == "Private" && header != "-----BEGIN RSA PRIVATE KEY-----")
            {
                System.Windows.MessageBox.Show("This file do not contain private key!");
                reader.Close();
                return;
            }
            else if (keyType == "Public" && header != "-----BEGIN RSA PUBLIC KEY-----") {
                System.Windows.MessageBox.Show("This file do not contain public key!");
                reader.Close();
                return;
            }
            string stringKey = reader.ReadToEnd();
            string[] lines = stringKey.Split('\n');
            lines[lines.Length - 2] = "";
            stringKey = String.Join('\n', lines);
            var rsa = System.Security.Cryptography.RSA.Create();
            RSAParameters paramss;
            if (keyType == "Private")
            {
                rsa.ImportRSAPrivateKey(Convert.FromBase64String(stringKey), out _);
                paramss = rsa.ExportParameters(true);
            }
            else {
                rsa.ImportRSAPublicKey(Convert.FromBase64String(stringKey), out _);
                paramss = rsa.ExportParameters(false);
            }
                
                var stringWriter = new StringWriter();
                var serializer = new XmlSerializer(typeof(RSAParameters));
                serializer.Serialize(stringWriter, paramss);
            if (keyType == "Private")
            {
                privKey = stringWriter.ToString();
            }
            else {
                pubKey = stringWriter.ToString();
            }
            System.Windows.MessageBox.Show("Read key succesfully!");
        }
        private void Button_Click(object sender, RoutedEventArgs e)
        {
            var message = Raw.Text;        //pobranie tekstu z okienka
            byte[] startMsg = Encoding.ASCII.GetBytes("Start");
            var bytes = new byte[1024];
            if (!isConnected) {
                System.Windows.MessageBox.Show("You are not connected to anyone!");
                return;
            }
            handler.Send(startMsg);                 //powiadomienie drugiego procesu o wysłaniu wiadomości
            int bytesRec = handler.Receive(bytes);
            var publicKey = Encoding.ASCII.GetString(bytes, 0, bytesRec);   //pobranie klucza publicznego wygenerowanego przez drugi proces                                                                  
            if (publicKey == "nic") {
                System.Windows.MessageBox.Show("Sender do not have keys");
                return;
            }
            var encrypted = Cryptography.RSA.Encrypt(message, publicKey);
            byte[] msgMsg = Encoding.ASCII.GetBytes(encrypted);             //zaszyfrowanie nim wiadomości i przesłanie drugiemu procesowi
            handler.Send(msgMsg);
            System.Windows.MessageBox.Show("Send encrypted message (RSA) succesfuly! " + encrypted);
        }

        private void Button_Click_OpenNewWindow(object sender, RoutedEventArgs e)
        {
            Process p = new Process();
            p.StartInfo.FileName = @"crpy2.exe";
            p.Start();
            Task t = new Task(startServer);
            t.Start();
        }
        //odbieranie wiadomości tekstowej
        private void reciveMessage()
        {
            Cryptography.RSA.GenerateKeys(out var privateKey, out var publicKey, keySize: 2048);   //wygenerowanie klucza publicznego i prywatnego
            byte[] msg = Encoding.ASCII.GetBytes(publicKey);
            byte[] hmsg = Encoding.ASCII.GetBytes("Sleep");
            handler.Send(hmsg);
            handler.Send(msg);                                  //przesłanie klucza publicznego procesowi nadającemu wiadomość
            if (pubKey == "nic")
            {
                System.Windows.MessageBox.Show("You don't have any key!");
                return;
            }
            var bytes = new byte[1024];
            int bytesRec = handler.Receive(bytes);
            var encMsg = Encoding.ASCII.GetString(bytes, 0, bytesRec);      //otrzymanie zaszyfrowanej wiadomości od drugiego procesu
            var message = Cryptography.RSA.Decrypt(encMsg, privateKey);         //odszyfrowanie otrzymanej wiadomości za pomocą klucza prywatnego
            Dispatcher.Invoke(new Action(() => { DecipheredMsg.Text = message; ; }));
            System.Windows.MessageBox.Show("Recived encrypted message (RSA) succesfuly! " + encMsg);
        }

        //wątek oczekujący na wiadomości
        private void messageHandler()
        {
            Dispatcher.Invoke(new Action(() => { Encrypted.Text = "Connected"; ; }));
            isConnected = true;
            var bytes = new byte[1024];
            string data = null;
            while (true) {
                int bytesRec = handler.Receive(bytes);
                data = Encoding.ASCII.GetString(bytes, 0, bytesRec);
                if (data == "Start")        //otrzymanie wiadomości tekstowej
                {
                    reciveMessage();
                }
                else if (data == "End" && isConnected)     //rozłączenie się
                {
                    byte[] msg = Encoding.ASCII.GetBytes("End2");
                    handler.Send(msg);
                    Dispatcher.Invoke(new Action(() => { Encrypted.Text = "Disconnected"; ; }));
                    isConnected = false;
                    break;
                }
                else if (data == "End2" && isConnected)
                {
                    Dispatcher.Invoke(new Action(() => { Encrypted.Text = "Disconnected"; ; }));
                    isConnected = false;
                    break;
                }
                else                        //nieotrzymanie żadnej wiadomości - proces jest nadawcą
                {
                    Thread.Sleep(1000);
                }
            }
        }
        //ustanowienie połączenia między procesami
        private void startServer()
        {
            IPHostEntry host = Dns.GetHostEntry("localhost");
            IPAddress ipAddress = host.AddressList[0];
            IPEndPoint localEndPoint = new IPEndPoint(ipAddress, 11000);
            Socket listener = new Socket(ipAddress.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
            listener.Bind(localEndPoint);
            listener.Listen(10);
            isServer = true;
            handler = listener.Accept();
            Task t = new Task(messageHandler);
            t.Start();
        }

        private void Button_Click_Connect(object sender, RoutedEventArgs e)
        {
            if (isServer) {
                System.Windows.MessageBox.Show("You currently waiting for connection! Try to use this function from second window");
                return;
            }
            IPHostEntry host = Dns.GetHostEntry("localhost");
            IPAddress ipAddress = host.AddressList[0];
            IPEndPoint remoteEP = new IPEndPoint(ipAddress, 11000);
            try
            {
                handler = new Socket(ipAddress.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
                handler.Connect(remoteEP);
            }
            catch (Exception ex) {
                System.Windows.MessageBox.Show("Error!");
                return;
            }
            Task t = new Task(messageHandler);
            t.Start();
        }
        //tworzenie zaszyfrowanych plików
        private void Button_Click_CipherFile(object sender, RoutedEventArgs e)
        {
            if (pubKey == null)
            {
                System.Windows.MessageBox.Show("Nie wybrałeś żadnego klucza");
                return;
            }
            OpenFileDialog openFileDialog = new OpenFileDialog();
            var result = openFileDialog.ShowDialog();
            if (result == System.Windows.Forms.DialogResult.Cancel) return;

            var file = openFileDialog.FileName;                  //wybór pliku do zaszyfrowania
            byte[] startMsg = Encoding.ASCII.GetBytes("StartFile");
            var bytes = new byte[1024];
            var publicKey = pubKey;
            byte[] password;
            byte[] salt = new byte[32];
            string sPassword;
            using (var cryptoProvider = new RNGCryptoServiceProvider())
            {
                password = new byte[64];
                cryptoProvider.GetBytes(password);
                sPassword = Encoding.ASCII.GetString(password);
                password = Encoding.ASCII.GetBytes(sPassword);
                for (int i = 0; i < 10; i++)
                {
                    // Fille the buffer with the generated data
                    cryptoProvider.GetBytes(salt);
                }
            }
            
            SymmetricAlgorithm alg;
            string algMode = (string)cb2.SelectedItem;
            if (algMode == "DES"){
                alg = new DESCryptoServiceProvider();
                alg.KeySize = 64;
                alg.BlockSize = 64;
            }
            else {
                alg = new RijndaelManaged();
                alg.KeySize = 256;
                alg.BlockSize = 128;
            }
            alg.Padding = PaddingMode.PKCS7;
            var key = new Rfc2898DeriveBytes(password, salt, 50000);
            alg.Key = key.GetBytes(alg.KeySize / 8);
            alg.IV = key.GetBytes(alg.BlockSize / 8);
            string mode = (string)cb.SelectedItem;
            switch (mode) {
                case "cbc":
                    alg.Mode = CipherMode.CBC;
                    break;
                case "ecb":
                    alg.Mode = CipherMode.ECB;
                    break;
                default:
                    alg.Mode = CipherMode.CBC;
                    break;
            }
            var ff = new FileStream(file + ".enc", FileMode.Create);    //utworzenie pliku, do którego zapiszemy zaszyfrowany plik
            CryptoStream cs = new CryptoStream(ff, alg.CreateEncryptor(), CryptoStreamMode.Write);
            var fw = new StreamWriter(file + ".meta");
            string encpsw = Cryptography.RSA.Encrypt(sPassword, publicKey);
            encMeta meta = new encMeta(mode, algMode, encpsw);
            string modeJson = JsonSerializer.Serialize(meta);
            fw.Write(modeJson);
            fw.Close();
            ff.Write(salt, 0, salt.Length);
            if (keys.ContainsKey(file + ".enc")) keys.Remove(file + ".enc");
            keys.Add(file + ".enc", sPassword);
            using (Stream source = File.OpenRead(file))
            {
                byte[] buffer = new byte[2048];                                 //ustalenie bloku na 2048b
                int bytesRead;
                while ((bytesRead = source.Read(buffer, 0, buffer.Length)) > 0)
                {
                    cs.Write(buffer, 0, bytesRead);
                }
                source.Close();
            }
            cs.Close();
            ff.Close();                                             //wysłanie ścieżki do zaszyfrowanego pliku
            System.Windows.MessageBox.Show("Encrypted file succesfuly!");
        }
        //odszyfrowanie zaszyfrowanego pliku
        private void Button_Click_DecipherFile(object sender, RoutedEventArgs e)
        {
            if (privKey == null)
            {
                System.Windows.MessageBox.Show("Nie wybrałeś żadnego klucza");
                return;
            }
            OpenFileDialog openFileDialog = new OpenFileDialog();
            openFileDialog.Filter = "Encrypted files (*.enc)|*.enc";
            var result = openFileDialog.ShowDialog();
            if (result == System.Windows.Forms.DialogResult.Cancel) return;
            var dfile = openFileDialog.FileName;                  //wybór pliku do deszyfrowania
            string file = dfile;
            string password = null;
            string modeJSON;
            try
            {
                StreamReader sr = new StreamReader(dfile.Substring(0, dfile.Length - 3) + "meta");
                modeJSON = sr.ReadToEnd();
                sr.Close();
            }
            catch (FileNotFoundException _) {
                System.Windows.MessageBox.Show(".meta file is missing! Cannot decipher file");
                return;
            }
            
            encMeta encMeta = JsonSerializer.Deserialize<encMeta>(modeJSON);
            string encPasword = encMeta.encKey;
            try
            {
                password = Cryptography.RSA.Decrypt(encPasword, privKey);
            }
            catch(System.Security.Cryptography.CryptographicException _) {
                System.Windows.MessageBox.Show("Wrong keys. Probably file is not dedicated for you");
                return;
            }
            string[] ww = file.Split('\\');
            string fileName = ww[ww.Length - 1];
            ww[ww.Length - 1] = "";
            string[] words = fileName.Split('.');
            string ffileName = words[0];
            string newFile = String.Join('\\', ww);
            newFile += ffileName + "(deciphred)";
            for(int i =1; i < words.Length - 1; i++)
            {
                newFile += "." + words[i];
            }
            byte[] salt = new byte[32];
            var ff = new FileStream(newFile, FileMode.Create);
            Stream src = File.OpenRead(file);
            src.Read(salt, 0, salt.Length);
            string algS = encMeta.alg;
            string mode = encMeta.mode;
            SymmetricAlgorithm alg;
            if (algS == "DES") {
                alg = new DESCryptoServiceProvider();
                alg.KeySize = 64;
                alg.BlockSize = 64;
            }
            else {
                alg = new RijndaelManaged();
                alg.KeySize = 256;
                alg.BlockSize = 128;
            }
            var key = new Rfc2898DeriveBytes(password, salt, 50000);
            alg.Key = key.GetBytes(alg.KeySize / 8);
            alg.IV = key.GetBytes(alg.BlockSize / 8);
            alg.Padding = PaddingMode.PKCS7;
            switch (mode) {
                case "cbc":
                    alg.Mode = CipherMode.CBC;
                    break;
                case "ecb":
                    alg.Mode = CipherMode.ECB;
                    break;
                default:
                    alg.Mode = CipherMode.CBC;
                    break;
            }
            CryptoStream cs = new CryptoStream(src, alg.CreateDecryptor(), CryptoStreamMode.Read);
            {
                byte[] buffer = new byte[2048];                                 //ustalenie bloku na 2048b
                int bytesRead;
                while ((bytesRead = cs.Read(buffer, 0, buffer.Length)) > 0)
                {
                    ff.Write(buffer, 0, bytesRead);
                }
                src.Close();
            }
            cs.Close();
            ff.Close();
            System.Windows.MessageBox.Show("Decrypted file succesfuly!");
        }
        //disconnection
        private void Button_Click_Disconnect(object sender, RoutedEventArgs e)
        {
            if (!isConnected) return;
            byte[] msg = Encoding.ASCII.GetBytes("End");
            handler.Send(msg);
        }
        private void Button_Click_Exit(object sender, RoutedEventArgs e)
        {
            if (isConnected)
            {
                Button_Click_Disconnect(sender, e);
            }
            System.Environment.Exit(0);
        }

        private void Window_Closing(object sender, System.ComponentModel.CancelEventArgs e)
        {
            Button_Click_Exit(sender, null);
        }
    }
}
