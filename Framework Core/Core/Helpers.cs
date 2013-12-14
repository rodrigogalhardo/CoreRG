using Microsoft.Web.WebPages.OAuth;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Web;
using System.Web.Http;
using System.Web.Mvc;
using System.Web.Services;
using System.Web.Helpers;
using System.Net.Mail;
using System.Web.UI;
using System.IO;
using System.Drawing;
using System.Drawing.Imaging;
using System.Text;
using System.Security;
using System.Security.Cryptography;



namespace CoreRG
{

    #region Classes - Criptografia

    /// <summary>
    /// Classe que Criptografa e Descriptgrafa informações
    /// </summary>
    public class Criptografia
    {
        /// <summary>
        /// Encripta um valor do tipo string, int, retornando o valor Criptografado
        /// USO: string query = Helpers.Criptografia.Encrypt(txtTexto.Text);
        /// </summary>
        /// <param name="data"></param>
        /// <returns></returns>
        public static string Encrypt(string data)
        {
            return Criptografar(data.Trim());
        }

        /// <summary>
        /// Decripta um valor Encriptado.
        /// USO: string query = Helpers.Criptografia.Decrypt(txtTexto.Text);
        /// </summary>
        /// <param name="data"></param>
        /// <returns></returns>
        public static string Decrypt(string data)
        {
            return Descriptografar(data.Trim());
        }

        /// <summary>
        /// Faz um encode/ hash de um valor passado usando a criptografia SHA1
        /// Muito usado para passwords e senhas, gera-se o hash e compara o que existe no banco para ver se são iguais.
        /// </summary>
        /// <param name="value"></param>
        /// <returns></returns>
        public static string Encode(string value)
        {
            var hash = System.Security.Cryptography.SHA1.Create();
            var encoder = new System.Text.ASCIIEncoding();
            var combined = encoder.GetBytes(value ?? "");
            return BitConverter.ToString(hash.ComputeHash(combined)).ToLower().Replace("-", "");
        }

        /// <summary>
        /// Gera uma chave aleatória e criptografa os dados informados pelo usuário fazendo uma fusão com a chave gerada.
        /// Tambem grava a informação gerada no registro do windows
        /// </summary>
        /// <param name="valor"></param>
        public static string GerarChaveECriptografar(string valor)
        {

            string GeneratedKey = "";

            System.Security.Cryptography.RNGCryptoServiceProvider rng = new System.Security.Cryptography.RNGCryptoServiceProvider();
            byte[] key = new byte[16];
            rng.GetBytes(key);
            string chave = Convert.ToBase64String(key);
            string saida = chave;

            //GravarNoRegistro(saida);
            chave = Criptografar(valor.Trim());

            return GeneratedKey;
        }

        protected static string Protect()
        {
            string chave = "EA81AA1D5FC1EC53E84F30AA746139EEBAFF8A9B76638895";

            try
            {
                byte[] segredo = System.Text.Encoding.ASCII.GetBytes(chave);
                byte[] entropia = { 10, 8, 4, 6, 5 };
                byte[] b = System.Security.Cryptography.ProtectedData.Protect(segredo, entropia, System.Security.Cryptography.DataProtectionScope.LocalMachine);
                return Convert.ToBase64String(b);
            }
            catch (System.Security.Cryptography.CryptographicException)
            {
                //
            }
            return null;
        }

        protected static string Unprotect()
        {
            string secret = "EA81AA1D5FC1EC53E84F30AA746139EEBAFF8A9B76638895";

            try
            {
                byte[] segredo = Convert.FromBase64String(secret);
                byte[] entropia = { 10, 8, 4, 6, 5 };
                byte[] b = System.Security.Cryptography.ProtectedData.Unprotect(segredo, entropia, System.Security.Cryptography.DataProtectionScope.LocalMachine);
                return Convert.ToBase64String(b);
            }
            catch (System.Security.Cryptography.CryptographicException)
            {
                //
            }
            return null;
        }

        /// <summary>
        /// Criptografa os dados e grava no registro do windows
        /// Usage: return txtCriptografados.Text = Criptografar(txtDados.Text.Trim(), Protect(ReadRegistro()));
        /// </summary>
        /// <param name="dados"></param>
        /// <param name="chave"></param>
        /// <returns></returns>
        private static string Criptografar(string dados)
        {
            string chave = "EA81AA1D5FC1EC53E84F30AA746139EEBAFF8A9B76638895";
            byte[] b = System.Text.Encoding.UTF8.GetBytes(dados);
            byte[] pw = System.Text.Encoding.UTF8.GetBytes(chave);

            System.Security.Cryptography.RijndaelManaged rm = new System.Security.Cryptography.RijndaelManaged();

            System.Security.Cryptography.PasswordDeriveBytes pdb = new System.Security.Cryptography.PasswordDeriveBytes(chave, new System.Security.Cryptography.MD5CryptoServiceProvider().ComputeHash(pw));
            rm.Key = pdb.GetBytes(32);
            rm.IV = pdb.GetBytes(16);
            rm.BlockSize = 128;
            rm.Padding = System.Security.Cryptography.PaddingMode.PKCS7;

            System.IO.MemoryStream ms = new System.IO.MemoryStream();

            System.Security.Cryptography.CryptoStream cryptStream = new System.Security.Cryptography.CryptoStream(ms, rm.CreateEncryptor(rm.Key, rm.IV), System.Security.Cryptography.CryptoStreamMode.Write);
            cryptStream.Write(b, 0, b.Length);
            cryptStream.FlushFinalBlock();
            return System.Convert.ToBase64String(ms.ToArray());
        }

        /// <summary>
        /// recupera a chave criptgrafada do registro baseado nos dados criptografados passado.
        /// Usage: return Descriptografar(Convert.FromBase64String(string dadosCritografados), Unprotect(ReadRegistro()));
        /// </summary>
        /// <param name="dados"></param>
        /// <param name="chave"></param>
        /// <returns></returns>
        private static string Descriptografar(string ddos)
        {
            byte[] dados = Convert.FromBase64String(ddos);

            string chave = "EA81AA1D5FC1EC53E84F30AA746139EEBAFF8A9B76638895";
            byte[] pw = System.Text.Encoding.UTF8.GetBytes(chave);

            System.Security.Cryptography.RijndaelManaged rm = new System.Security.Cryptography.RijndaelManaged();
            System.Security.Cryptography.PasswordDeriveBytes pdb = new System.Security.Cryptography.PasswordDeriveBytes(chave, new System.Security.Cryptography.MD5CryptoServiceProvider().ComputeHash(pw));
            rm.Key = pdb.GetBytes(32);
            rm.IV = pdb.GetBytes(16);
            rm.BlockSize = 128;
            rm.Padding = System.Security.Cryptography.PaddingMode.PKCS7;

            System.IO.MemoryStream ms = new System.IO.MemoryStream(dados, 0, dados.Length);

            System.Security.Cryptography.CryptoStream cryptStream = new System.Security.Cryptography.CryptoStream(ms, rm.CreateDecryptor(rm.Key, rm.IV), System.Security.Cryptography.CryptoStreamMode.Read);
            System.IO.StreamReader sr = new System.IO.StreamReader(cryptStream);
            return sr.ReadToEnd();
        }

        [System.Security.Permissions.RegistryPermission(System.Security.Permissions.SecurityAction.Demand, Create = @"HKEY_LOCAL_MACHINE\Software\Microsoft\ChaveCriptografada")]
        static void GravarNoRegistro(string valor)
        {
            try
            {
                Microsoft.Win32.RegistryKey rk = Microsoft.Win32.Registry.LocalMachine.OpenSubKey("Software\\microsoft", true);
                Microsoft.Win32.RegistryKey chave = rk.CreateSubKey("ChaveTeste");
                chave.SetValue("key", valor);
            }
            catch (UnauthorizedAccessException)
            {
                //
            }
            catch (System.Security.SecurityException)
            {
                //
            }
            catch (Exception)
            {
                //
            }
        }

        [System.Security.Permissions.RegistryPermission(System.Security.Permissions.SecurityAction.Demand, Read = @"HKEY_LOCAL_MACHINE\Software\Microsoft\ChaveCriptografada")]
        public static string ReadRegistro()
        {
            Microsoft.Win32.RegistryKey ch = Microsoft.Win32.Registry.LocalMachine.OpenSubKey("Software\\Microsoft\\ChaveCriptografada", false);
            return ch.GetValue("key") as string;
        }

        #region MD5 Generator

        /// <summary>
        /// KeyString: Recebe os dados dos parametros -> KeyName + KeyParam para gerar o MD5
        /// KeyStr é o retorno/saida do resultado do MD5, return KeyStr
        /// KeyParam: Poder ser qualquer coisa, nome, email, etc. ou dados variaveis vindo do banco de dados
        /// KeyName: Idem ao KeyParam, pois um sera concatenado com o outro para gerar uma chave MD5 mais segura.
        /// </summary>
        /// <param name="KeyString"></param>
        /// <param name="KeyStr"></param>
        /// <param name="KeyName"></param>
        /// <param name="KeyParam"></param>
        /// <returns></returns>
        public static string MD5Generator(string KeyName, string KeyParam)
        {
            string KeyString = KeyName + "-" + KeyParam;

            System.Security.Cryptography.MD5 md5 = System.Security.Cryptography.MD5.Create();
            byte[] inputBytes = System.Text.Encoding.ASCII.GetBytes(KeyString);
            byte[] hash = md5.ComputeHash(inputBytes);
            System.Text.StringBuilder sb = new System.Text.StringBuilder();

            for (int i = 0; i < hash.Length; i++)
            {
                sb.Append(hash[i].ToString("X2"));
            }
            string KeyStr = sb.ToString();

            return KeyStr;

        }

        #endregion

        #region Utils de Criptografia

        private static Byte[] ConvertStringToByArray(string s)
        {
            return (new UnicodeEncoding()).GetBytes(s);
        }

        private static string MD5(string s)
        {
            if (string.IsNullOrEmpty(s))
            {
                return null;
            }
            Byte[] toHash = ConvertStringToByArray(s);
            byte[] hashValue = ((System.Security.Cryptography.HashAlgorithm)System.Security.Cryptography.CryptoConfig.CreateFromName("MD5")).ComputeHash(toHash);
            return BitConverter.ToString(hashValue);
        }

        private static string Base64Encode(string key)
        {
            if (string.IsNullOrEmpty(key))
                return string.Empty;

            byte[] buffer = Encoding.UTF8.GetBytes(key);
            return Convert.ToBase64String(buffer);
        }

        private static string Base64Decode(string key)
        {
            if (string.IsNullOrEmpty(key))
                return "";

            byte[] buffer = Convert.FromBase64String(key);
            return Encoding.UTF8.GetString(buffer);
        }

        // Arbitrary key and iv vector.
        // You will want to generate (and protect) your own when using encryption.
        private const string actionKey = "EA81AA1D5FC1EC53E84F30AA746139EEBAFF8A9B76638895";
        private const string actionIv = "87AF7EA221F3FFF5";

        public static System.Security.Cryptography.TripleDESCryptoServiceProvider des3;

        public Criptografia()
        {
            des3 = new System.Security.Cryptography.TripleDESCryptoServiceProvider();
            des3.Mode = System.Security.Cryptography.CipherMode.CBC;
        }

        private string GenerateKey()
        {
            des3.GenerateKey();
            return BytesToHex(des3.Key);
        }

        public string GenerateIV()
        {
            des3.GenerateIV();
            return BytesToHex(des3.IV);
        }

        private static byte[] HexToBytes(string hex)
        {
            byte[] bytes = new byte[hex.Length / 2];
            for (int i = 0; i < hex.Length / 2; i++)
            {
                string code = hex.Substring(i * 2, 2);
                bytes[i] = byte.Parse(code, System.Globalization.NumberStyles.HexNumber);
            }
            return bytes;
        }

        private static string BytesToHex(byte[] bytes)
        {
            StringBuilder hex = new StringBuilder();
            for (int i = 0; i < bytes.Length; i++)
                hex.AppendFormat("{0:X2}", bytes[i]);
            return hex.ToString();
        }


        public static string Encrypt(string data, string key, string iv)
        {
            byte[] bdata = Encoding.UTF8.GetBytes(data);
            byte[] bkey = HexToBytes(key);
            byte[] biv = HexToBytes(iv);

            MemoryStream stream = new MemoryStream();
            CryptoStream encStream = new CryptoStream(stream, des3.CreateEncryptor(bkey, biv), CryptoStreamMode.Write);

            encStream.Write(bdata, 0, bdata.Length);
            encStream.FlushFinalBlock();
            encStream.Close();

            return BytesToHex(stream.ToArray());
        }

        private static string Decrypt(string data, string key, string iv)
        {
            byte[] bdata = HexToBytes(data);
            byte[] bkey = HexToBytes(key);
            byte[] biv = HexToBytes(iv);

            MemoryStream stream = new MemoryStream();
            System.Security.Cryptography.CryptoStream encStream = new System.Security.Cryptography.CryptoStream(stream,
             des3.CreateDecryptor(bkey, biv), System.Security.Cryptography.CryptoStreamMode.Write);

            encStream.Write(bdata, 0, bdata.Length);
            encStream.FlushFinalBlock();
            encStream.Close();

            return Encoding.UTF8.GetString(stream.ToArray());
        }

        #endregion
    }

    #endregion

    #region Validadores

    /// <summary>
    /// Classe que Valida dados : 13 Funcoes
    /// </summary>
    public class Validator
    {
        #region Validações

        static bool validado;

        /// <summary>
        /// Metodo que valida o Email
        /// </summary>
        /// <param name="_Email"></param>
        /// <returns></returns>
        public static bool ValidaEmail(string _Email)
        {
            System.Text.RegularExpressions.Regex em = new System.Text.RegularExpressions.Regex(@"^[A-Za-z0-9](([_\.\-]?[a-zA-Z0-9]+)*)@([A-Za-z0-9]+)(([\.\-]?[a-zA-Z0-9]+)*)\.([A-Za-z]{2,})$");
            if (em.IsMatch(_Email))
                validado = true;
            else
                validado = false;

            return validado;
        }

        /// <summary>
        /// Metodo que retorna um booleano validador de CPF
        /// </summary>
        /// <param name="_CPF"></param>
        /// <returns></returns>
        public static bool ValidaCPF(string _CPF)
        {
            //Método que valida o CPF
            string valor = _CPF.Replace(".", "");
            valor = valor.Replace("-", "");

            if (valor.Length != 11)
                return false;

            bool igual = true;
            for (int i = 1; i < 11 && igual; i++)
                if (valor[i] != valor[0])
                    igual = false;

            if (igual || valor == "12345678909")
                return false;

            int[] numeros = new int[11];
            for (int i = 0; i < 11; i++)
                numeros[i] = int.Parse(
                valor[i].ToString());

            int soma = 0;
            for (int i = 0; i < 9; i++)
                soma += (10 - i) * numeros[i];

            int resultado = soma % 11;
            if (resultado == 1 || resultado == 0)
            {
                if (numeros[9] != 0)
                    return false;
            }
            else if (numeros[9] != 11 - resultado)
                return false;

            soma = 0;
            for (int i = 0; i < 10; i++)
                soma += (11 - i) * numeros[i];

            resultado = soma % 11;

            if (resultado == 1 || resultado == 0)
            {
                if (numeros[10] != 0)
                    return false;

            }
            else
                if (numeros[10] != 11 - resultado)
                    validado = false; //return false;
                else
                    validado = true;

            return validado;//return true;
        }

        /// <summary>
        /// Metodo que retorna um um booleano que valida o CNPJ
        /// </summary>
        /// <param name="_CNPJ"></param>
        /// <returns></returns>
        public static bool ValidaCNPJ(string _CNPJ)
        {

            string CNPJ = _CNPJ.Replace(".", "");
            CNPJ = CNPJ.Replace("/", "");
            CNPJ = CNPJ.Replace("-", "");

            int[] digitos, soma, resultado;
            int nrDig;
            string ftmt;
            bool[] CNPJOk;

            ftmt = "6543298765432";
            digitos = new int[14];
            soma = new int[2];
            soma[0] = 0;
            soma[1] = 0;
            resultado = new int[2];
            resultado[0] = 0;
            resultado[1] = 0;
            CNPJOk = new bool[2];
            CNPJOk[0] = false;
            CNPJOk[1] = false;

            try
            {
                for (nrDig = 0; nrDig < 14; nrDig++)
                {
                    digitos[nrDig] = int.Parse(
                     CNPJ.Substring(nrDig, 1));
                    if (nrDig <= 11)
                        soma[0] += (digitos[nrDig] *
                        int.Parse(ftmt.Substring(
                          nrDig + 1, 1)));
                    if (nrDig <= 12)
                        soma[1] += (digitos[nrDig] *
                        int.Parse(ftmt.Substring(
                          nrDig, 1)));
                }

                for (nrDig = 0; nrDig < 2; nrDig++)
                {
                    resultado[nrDig] = (soma[nrDig] % 11);
                    if ((resultado[nrDig] == 0) || (resultado[nrDig] == 1))
                        CNPJOk[nrDig] = (
                        digitos[12 + nrDig] == 0);

                    else
                        CNPJOk[nrDig] = (
                        digitos[12 + nrDig] == (
                        11 - resultado[nrDig]));

                }

                validado = CNPJOk[0] && CNPJOk[1];

                return validado;

            }
            catch
            {
                return false;
            }

        }

        /// <summary>
        /// Verifica se o texto retorna um objeto do tipo null, e converte para um objeto do tipo string. para ficar mais facil manipular
        /// </summary>
        /// <param name="Texto"></param>
        /// <returns></returns>
        public static string Ve_Nulo(Object Texto)
        {
            if (Texto == null)
                return "";
            else
                return Convert.ToString(Texto);
        }

        /// <summary>
        /// Verifica se o texto retorna um objeto do típo INT é NULL e converte para 0, e se nao e null ele verifica se o objeto e do tipo numerico, e tambem retorna algum valor.
        /// </summary>
        /// <param name="Valor"></param>
        /// <returns></returns>
        public static int Ve_Valor(Object Valor)
        {
            if (Valor == null)
                return 0;
            else
            {
                if (Convert.ToString(Valor).Length == 0 || !IsNumeric(Valor))
                    return 0;
                else
                    return Convert.ToInt32(Valor);
            }
        }

        /// <summary>
        /// Verifica se o objeto é do tipo Inteiro (INT)
        /// </summary>
        /// <param name="Valor"></param>
        /// <returns></returns>
        public static Boolean IsNumeric(object Valor)
        {
            //Variavel para retorno da conversao
            int resultado;

            //Utilizo o TryParse, para a validação do objeto, verificando se é inteiro
            if (int.TryParse(Valor.ToString(), out resultado))
            {
                //O resulto é exposto, reparem que caso a conversão seja feita além de retornar um booleano, ele retorna o resultado da conversão através de um parametro OUT.
                return true;
            }
            else
                return false;
        }

        /// <summary>
        /// Verifica so o objeto é do tipo Double, fazendo a devida conversão e retornado True, caso seja. senao é false.
        /// </summary>
        /// <param name="Valor"></param>
        /// <returns></returns>
        public static Boolean IsDouble(string Valor)
        {
            try
            {
                double doub = double.Parse(Valor);
                return true;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Verifica se o objeto é do tipo Date(Data) retornando True, caso nao retorna False.
        /// </summary>
        /// <param name="Valor"></param>
        /// <returns></returns>
        public static Boolean IsDate(string Valor)
        {
            DateTime dt;
            bool isDate = true;
            try
            {
                dt = DateTime.Parse(Valor);
            }
            catch
            {
                return false;
            }
            return isDate;
        }

        /// <summary>
        /// Retirar todos os acentos do texto informado
        /// 
        /// </summary> 
        /// <param name="texto">String para retirar acentos</param>
        /// <returns>String do texto sem acentos</returns>
        public static string TirarAcentos(string texto)
        {
            string textor = "";

            for (int i = 0; i < texto.Length; i++)
            {
                if (texto[i].ToString() == "ã") textor += "a";
                else if (texto[i].ToString() == "á") textor += "a";
                else if (texto[i].ToString() == "à") textor += "a";
                else if (texto[i].ToString() == "â") textor += "a";
                else if (texto[i].ToString() == "ä") textor += "a";
                else if (texto[i].ToString() == "é") textor += "e";
                else if (texto[i].ToString() == "è") textor += "e";
                else if (texto[i].ToString() == "ê") textor += "e";
                else if (texto[i].ToString() == "ë") textor += "e";
                else if (texto[i].ToString() == "í") textor += "i";
                else if (texto[i].ToString() == "ì") textor += "i";
                else if (texto[i].ToString() == "ï") textor += "i";
                else if (texto[i].ToString() == "õ") textor += "o";
                else if (texto[i].ToString() == "ó") textor += "o";
                else if (texto[i].ToString() == "ò") textor += "o";
                else if (texto[i].ToString() == "ö") textor += "o";
                else if (texto[i].ToString() == "ú") textor += "u";
                else if (texto[i].ToString() == "ù") textor += "u";
                else if (texto[i].ToString() == "ü") textor += "u";
                else if (texto[i].ToString() == "ç") textor += "c";
                else if (texto[i].ToString() == "Ã") textor += "A";
                else if (texto[i].ToString() == "Á") textor += "A";
                else if (texto[i].ToString() == "À") textor += "A";
                else if (texto[i].ToString() == "Â") textor += "A";
                else if (texto[i].ToString() == "Ä") textor += "A";
                else if (texto[i].ToString() == "É") textor += "E";
                else if (texto[i].ToString() == "È") textor += "E";
                else if (texto[i].ToString() == "Ê") textor += "E";
                else if (texto[i].ToString() == "Ë") textor += "E";
                else if (texto[i].ToString() == "Í") textor += "I";
                else if (texto[i].ToString() == "Ì") textor += "I";
                else if (texto[i].ToString() == "Ï") textor += "I";
                else if (texto[i].ToString() == "Õ") textor += "O";
                else if (texto[i].ToString() == "Ó") textor += "O";
                else if (texto[i].ToString() == "Ò") textor += "O";
                else if (texto[i].ToString() == "Ö") textor += "O";
                else if (texto[i].ToString() == "Ú") textor += "U";
                else if (texto[i].ToString() == "Ù") textor += "U";
                else if (texto[i].ToString() == "Ü") textor += "U";
                else if (texto[i].ToString() == "Ç") textor += "C";
                else textor += texto[i];
            }
            return textor;
        }

        /// <summary>
        /// Retira os acentos do texto informado de acordo com o ISO-8859-8, modo simples.
        /// </summary>
        /// <param name="input"></param>
        /// <returns></returns>
        public static string TirarAcentos2(string input)
        {
            if (string.IsNullOrEmpty(input))
                return "";
            else
            {
                byte[] bytes = System.Text.Encoding.GetEncoding("iso-8859-8").GetBytes(input);
                return System.Text.Encoding.UTF8.GetString(bytes);
            }
        }



        #endregion

        #region Alerta

        /// <summary>
        /// Exibe uma mensagem de alerta na página.
        /// </summary>
        /// <param name="mensagem"></param>
        /// <param name="page"></param>
        public static void ExibirMensagem(string mensagem, Page page)
        {
            page.ClientScript.RegisterStartupScript(System.Type.GetType("System.String"), "Alert",
               "<script language='javascript'> { window.alert(\"" + mensagem + "\") }</script>");
        }

        #endregion

        #region Enviar Email

        /// <summary>
        /// DE: Remetente
        /// Para: Destinatário
        /// Titulo: Titulo do Email
        /// Corpo: Corpo do Email, HTML, StreamReader e etc
        /// Bcc: Cópia Oculta
        /// cCopia: Envia uma cópia do email, é visivel para os outros usuarios
        /// Atach: Anexo de arquivos
        /// hHost: Localhost(quando estiver dentro do servidor web), SMTP.DOMINIO.COM
        /// hPort: Porta SMTP, padrão: 587
        /// hCredential: Usuario do SMTP (Para autenticação)
        /// hPswd: Senha do SMTP (Para Autenticação)
        /// </summary>
        /// <param name="De"></param>
        /// <param name="Para"></param>
        /// <param name="Titulo"></param>
        /// <param name="Corpo"></param>
        /// <param name="Bcc"></param>
        /// <param name="cCopia"></param>
        /// <param name="Atach"></param>
        /// <param name="hHost"></param>
        /// <param name="hPort"></param>
        /// <param name="hCredential"></param>
        /// <param name="hPswd"></param>
        /// <returns></returns>
        public static string EnvioEmail(string De, string Para, string Titulo, string Corpo, string Bcc, string cCopia, string Atach, string hHost, int hPort, string hCredential, string hPswd)
        {
            String sErro = "";

            try
            {
                //string strCorpo = "teste";

                System.Net.Mail.MailMessage email = new System.Net.Mail.MailMessage();
                String[] arrPara = Para.Split(';');
                for (int z = 0; z < arrPara.Length; z++)
                {
                    email.To.Add(Convert.ToString(arrPara[z]));
                }

                email.From = new MailAddress(De);

                if (Convert.ToString(Bcc) != "")
                {
                    String[] arrBcc = Bcc.Split(';');
                    for (int z = 0; z < arrBcc.Length; z++)
                    {
                        email.Bcc.Add(Convert.ToString(arrBcc[z]));
                    }

                    //objEmail.Bcc.Add(Impactro.Util.GetString(strBcc));
                }
                if (Convert.ToString(cCopia) != "")
                {
                    String[] arrCopia = cCopia.Split(';');
                    for (int y = 0; y < arrCopia.Length; y++)
                    {
                        email.CC.Add(Convert.ToString(arrCopia[y]));
                    }
                }

                //email.SubjectEncoding = Encoding.GetEncoding("iso-8859-1");

                email.Subject = Titulo;
                email.Body = Corpo;
                email.IsBodyHtml = true;

                //System.Web.Mail.MailMessage objEmail = new System.Web.Mail.MailMessage();


                ////AUTENTICACAO NO SERVIDOR DE EMAIL
                //objEmail.Fields["http://schemas.microsoft.com/cdo/configuration/smtpauthenticate"] = 1;
                //objEmail.Fields["http://schemas.microsoft.com/cdo/configuration/sendusername"] = "direct@portaldosjornalistas";
                //objEmail.Fields["http://schemas.microsoft.com/cdo/configuration/sendpassword"] = "pj2011@";

                //objEmail.From = strDe;
                //objEmail.To = strPara;//"";
                //// string emailcc = "";
                ////if (Ve_Nulo(emailcc) != "")
                ////    objEmail.Cc = emailcc;

                //string emailbcc = System.Configuration.ConfigurationManager.AppSettings["EmailCopia"].ToString();

                //if (Ve_Nulo(strBcc) != "")
                //    objEmail.Bcc = strBcc;

                ////strTitulo = "teste";
                ////strCorpo = "mensagem";
                //objEmail.Subject = strTitulo;
                //objEmail.Body = strCorpo;
                //objEmail.BodyFormat = System.Web.Mail.MailFormat.Html;

                //if (Ve_Nulo(strAtach) != "")
                //{
                //    MailAttachment anexo = new MailAttachment(strAtach);
                //    objEmail.Attachments.Add(anexo);
                //}
                System.Net.Mail.SmtpClient smtp = new System.Net.Mail.SmtpClient
                {
                    Host = hHost,
                    Port = hPort,
                    //Host = "localhost",
                    //Port = 587,

                    //UseDefaultCredentials = false,
                    //DeliveryMethod = SmtpDeliveryMethod.Network,
                    //Credentials = new System.Net.NetworkCredential("comunidado@homebr", "homebr2013@"),

                    Credentials = new System.Net.NetworkCredential(hCredential, hPswd),
                    Timeout = 10000
                };
                smtp.Send(email);

                //System.Web.Mail.SmtpMail.SmtpServer = "homebr.com.br";
                //System.Web.Mail.SmtpMail.Send(objEmail);
                sErro = "Email enviado com sucesso!!!!";
            }
            catch (Exception ex)
            {
                sErro = "Error no send: " + ex.ToString();
            }
            return sErro;

        }

        /// <summary>
        /// Envia email usando a classe Webmail, tem que ser configurado a porta SmtpServer, SmtpPort, UserName, Password - Forma mais simples
        /// </summary>
        /// <param name="Email"></param>
        /// <param name="Nome"></param>
        /// <param name="Assunto"></param>
        /// <param name="BodyMensagem"></param>
        /// <param name="Para"></param>
        /// <param name="ContatoTelefonico"></param>
        /// <param name="SmtpServer"></param>
        /// <param name="SmtpPort"></param>
        /// <param name="UserName"></param>
        /// <param name="Password"></param>
        /// <param name="From"></param>
        /// <returns></returns>
        public static string EnviarWebMail(string Email, string Nome, string Assunto, string BodyMensagem, string Para, string ContatoTelefonico, string SmtpServer, int SmtpPort, string UserName, string Password, string From)
        {
            string stringSuss = "";

            try
            {
                WebMail.SmtpServer = SmtpServer; //Obtem ou Define o nome do servidor SMTP para transmitir a mensagem de email
                WebMail.SmtpPort = SmtpPort; //Obtem ou Define a porta usada para transações SMTP
                WebMail.UserName = UserName; //Obtem ou Define o endereco de email da conta usada para enviar o email
                WebMail.Password = Password; //Obtem ou Define a senha da conta do remetente
                WebMail.From = From; //Obtem ou Define o endereco do remetente
                WebMail.Send(
                    to: "Nome: " + Nome + "Email :" + Email,
                    subject: "Assunto: " + Assunto,
                    body: "Telefone: " + ContatoTelefonico + "Para Dpto:" + Para + "Mensagem: " + BodyMensagem
                    );

                stringSuss = "Enviado com sucesso!";

                return stringSuss;
            }
            catch (Exception ex)
            {
                stringSuss = "Email não Pode ser enviado!";
                return ((stringSuss + ex).ToString());
            }


        }

        #endregion

    }

    #endregion

    #region Formatação de Valores

    /// <summary>
    /// Classe usada para formatação de valores : 24 funcoes
    /// </summary>
    public class Formatar
    {

        #region Formataçao de valores
        /// <summary>
        /// Formata valores decimais com duas casas
        /// ex: 123.4567 => 123.46 ou 123.0 => 123.00
        /// </summary>
        /// <param name="dados"></param>
        /// <returns></returns>
        public static string DecimalTwoPlaces(string dados)
        {
            return String.Format("{0:0.00}", dados);
        }

        /// <summary>
        /// Formata valores decimais com o Max de duas casas
        /// ex: 123.4567 => 123.46 ou 123.0 => 123
        /// </summary>
        /// <param name="dados"></param>
        /// <returns></returns>
        public static string DecimalMaxPlaces(string dados)
        {
            return String.Format("{0:0.##}", dados);
        }

        /// <summary>
        /// Formata valores com os ultimos dois digitos depois do ponto decimal.
        /// ex: 3.4567 => 03.4
        /// </summary>
        /// <param name="dados"></param>
        /// <returns></returns>
        public static string DecimalTwoDigtsBeforePoint(string dados)
        {
            return String.Format("{0:00.0}", dados);
        }

        /// <summary>
        /// Formata valores milhares.
        /// ex: 12345.67 => 12.345,67
        /// </summary>
        /// <param name="dados"></param>
        /// <returns></returns>
        public static string Milhar(string dados)
        {
            return String.Format("{0:0,0.00}", dados);
        }

        /// <summary>
        /// Formata valores milhares sem as ultimas duas casas decimais.
        /// ex: 12345.67 => 12.345
        /// </summary>
        /// <param name="dados"></param>
        /// <returns></returns>
        public static string MilharWithoutCentsPlace(string dados)
        {
            return String.Format("{0:0,0}", dados);
        }

        #endregion

        #region Formatação de Datas e Horas

        /// <summary>
        /// Retorna a Hora formatada no Fomato 24 Horas
        /// ex: 13:28:48  HH=24h
        /// </summary>
        /// <param name="hora"></param>
        /// <returns></returns>
        public static string DHHMMSS24h(string hora)
        {
            string h = String.Format("{0:HH:mm:ss}", hora);

            return h;
        }

        /// <summary>
        /// Retorna a hora formatada no formato de 12 Horas.
        /// ex: 01:28:48 hh=12hs
        /// </summary>
        /// <param name="hora"></param>
        /// <returns></returns>
        public static string DHHMMSS12h(string hora)
        {
            string h = String.Format("{0:hh:mm:ss}", hora);

            return h;
        }

        /// <summary>
        /// Formata a data e a hora em Extenso.
        /// Ex: 12 de dezembro de 2009 13:40:05
        /// </summary>
        /// <param name="diahora"></param>
        /// <returns></returns>
        public static string DDHHExtenso(string diahora)
        {
            string h = String.Format("{0:dd 'de' MMMM 'de' yyyy HH:mm:ss}", diahora);

            return h;
        }

        /// <summary>
        /// Formata Data no formato: 07/02/2013
        /// </summary>
        /// <param name="data"></param>
        /// <returns></returns>
        public static string DDMMYYYY(string data)
        {
            string d = String.Format("{0:dd/MM/yyyy}", data);

            return d;
        }

        /// <summary>
        /// Formata a data no padrão 24 horas, padrão C# {0:d}.
        /// ex: 29/12/2009
        /// </summary>
        /// <param name="data"></param>
        /// <returns></returns>
        public static string D24(string data)
        {
            string d = String.Format("{0:d}", data);

            return d;
        }

        /// <summary>
        /// Formata a data em extenso de Semana, dia mes e ano.
        /// ex: segunda-feira, 7 de dezembro de 2011
        /// </summary>
        /// <param name="data"></param>
        /// <returns></returns>
        public static string DWeekDayMonthYear(string data)
        {
            string d = String.Format("{0:D}", data);

            return d;
        }

        /// <summary>
        /// Formata a data em extenso de Semana, dia mes e ano e Hora 24Hs
        /// </summary>
        /// <param name="data"></param>
        /// <returns></returns>
        public static string DWeekDayMonthYearHour(string data)
        {
            string d = String.Format("{0:F}", data);

            return d;
        }

        /// <summary>
        /// Formata a data e hora em um formado de: DD/MM/YYYY + 13:12:20 24Hs
        /// ex: 29/12/2009 13:12:20
        /// </summary>
        /// <param name="data"></param>
        /// <returns></returns>
        public static string DH24hs(string data)
        {
            string d = String.Format("{0:G}", data);

            return d;
        }

        /// <summary>
        /// Formata a data e a hora sem o segundos.
        /// ex: 08/04/2011 14:25
        /// </summary>
        /// <param name="data"></param>
        /// <returns></returns>
        public static string DH24sm(string data)
        {
            string d = String.Format("{0:g}", data);

            return d;
        }

        /// <summary>
        /// Formata a data em formato de Mes e Ano.
        /// ex: maio de 2010
        /// </summary>
        /// <param name="data"></param>
        /// <returns></returns>
        public static string DMonthYear(string data)
        {
            string d = String.Format("{0:Y}", data);
            return d;
        }

        /// <summary>
        /// Formata a data, hora em um formado de: dom, 08 de maio 2011 13:40:05 GMT 
        /// </summary>
        /// <param name="data"></param>
        /// <returns></returns>
        public static string DWeekDayMonthYearHour24(string data)
        {
            string d = String.Format("{0:R}", data);

            return d;
        }

        /// <summary>
        /// Mostra o Fuso horário de uma hora.
        /// </summary>
        /// <param name="data"></param>
        /// <returns></returns>
        public static string DTimeZone(string data)
        {
            string d = String.Format("{0:z zz zzz}", data);

            return d;
        }

        #endregion

        #region Reverter String

        /// <summary>
        /// Reverte uma string de:  Hello World ; Para: dlroW olleH
        /// </summary>
        /// <param name="str"></param>
        /// <returns></returns>
        public static string ReverseString(string str)
        {
            char[] arr = str.ToCharArray();
            Array.Reverse(arr);
            return new string(arr);
        }

        #endregion

        #region Formatação de Dados Geográficos

        public static string CoordinateLatLng(double Latitude, double Longitude)
        {
            return String.Format(@"{0:00\.0000000}", Latitude) + ", " + String.Format(@"{0:00\.0000000}", Longitude);
        }

        public static string CoordinateLat(double Latitude)
        {
            return String.Format(@"{0:00\.0000000}", Latitude);
        }

        public static string CoordinateLng(double Longitude)
        {
            return String.Format(@"{0:00\.0000000}", Longitude);
        }

        #endregion

        #region Função para escrever por extenso os valores em Real (em C# - suporta até R$ 9.999.999.999,99)

        /// <summary>
        /// Função para escrever por extenso os valores em Real (em C# - suporta até R$ 9.999.999.999,99)     
        /// Rotina Criada para ler um número e transformá-lo em extenso                                       
        /// Limite máximo de 9 Bilhões (9.999.999.999,99).
        /// Não aceita números negativos. 
        /// LinhadeCodigo.com.br Autor: José F. Mar / Milton P. Jr
        /// Reconstruido e Modificado por Rodrigo Galhardo
        /// </summary> 
        /// <param name="do_Valor">Valor para converter em extenso. Limite máximo de 9 Bilhões (9.999.999.999,99).</param>
        /// <returns>String do valor por Extenso</returns> 
        /// USE: 
        /// Decimal valor_decimal = 123.45m;
        /// string Valor = CoreRG.Formatar.ValorPorExtenso(valor_decimal);
        /// 
        public static string ValorPorExtenso(decimal do_Valor)
        {
            string strValorExtenso = ""; //Variável que irá armazenar o valor por extenso do número informado
            string strNumero = "";       //Irá armazenar o número para exibir por extenso 
            string strCentena = "";
            string strDezena = "";
            string strDezCentavo = "";

            decimal dblCentavos = 0;
            decimal dblValorInteiro = 0;
            int intContador = 0;
            bool bln_Bilhao = false;
            bool bln_Milhao = false;
            bool bln_Mil = false;
            bool bln_Unidade = false;

            //Verificar se foi informado um dado indevido 
            if (do_Valor == 0 || do_Valor <= 0)
            {
                throw new Exception("Valor não suportado pela Função. Verificar se há valor negativo ou nada foi informado");
            }
            if (do_Valor > (decimal)9999999999.99)
            {
                throw new Exception("Valor não suportado pela Função. Verificar se o Valor está acima de 9999999999.99");
            }
            else //Entrada padrão do método
            {
                //Gerar Extenso Centavos 
                do_Valor = (Decimal.Round(do_Valor, 2));
                dblCentavos = do_Valor - (Int64)do_Valor;

                //Gerar Extenso parte Inteira
                dblValorInteiro = (Int64)do_Valor;
                if (dblValorInteiro > 0)
                {
                    if (dblValorInteiro > 999)
                    {
                        bln_Mil = true;
                    }
                    if (dblValorInteiro > 999999)
                    {
                        bln_Milhao = true;
                        bln_Mil = false;
                    }
                    if (dblValorInteiro > 999999999)
                    {
                        bln_Mil = false;
                        bln_Milhao = false;
                        bln_Bilhao = true;
                    }

                    for (int i = (dblValorInteiro.ToString().Trim().Length) - 1; i >= 0; i--)
                    {
                        // strNumero = Mid(dblValorInteiro.ToString().Trim(), (dblValorInteiro.ToString().Trim().Length - i) + 1, 1);
                        strNumero = Mid(dblValorInteiro.ToString().Trim(), (dblValorInteiro.ToString().Trim().Length - i) - 1, 1);
                        switch (i)
                        {            /*******/
                            case 9:  /*Bilhão*
                                 /*******/
                                {
                                    strValorExtenso = fcn_Numero_Unidade(strNumero) + ((int.Parse(strNumero) > 1) ? " Bilhões e" : " Bilhão e");
                                    bln_Bilhao = true;
                                    break;
                                }
                            case 8: /********/
                            case 5: //Centena*
                            case 2: /********/
                                {
                                    if (int.Parse(strNumero) > 0)
                                    {
                                        strCentena = Mid(dblValorInteiro.ToString().Trim(), (dblValorInteiro.ToString().Trim().Length - i) - 1, 3);

                                        if (int.Parse(strCentena) > 100 && int.Parse(strCentena) < 200)
                                        {
                                            strValorExtenso = strValorExtenso + " Cento e ";
                                        }
                                        else
                                        {
                                            strValorExtenso = strValorExtenso + " " + fcn_Numero_Centena(strNumero);
                                        }
                                        if (intContador == 8)
                                        {
                                            bln_Milhao = true;
                                        }
                                        else if (intContador == 5)
                                        {
                                            bln_Mil = true;
                                        }
                                    }
                                    break;
                                }
                            case 7: /*****************/
                            case 4: //Dezena de Milhão*
                            case 1: /*****************/
                                {
                                    if (int.Parse(strNumero) > 0)
                                    {
                                        strDezena = Mid(dblValorInteiro.ToString().Trim(), (dblValorInteiro.ToString().Trim().Length - i) - 1, 2);//

                                        if (int.Parse(strDezena) > 10 && int.Parse(strDezena) < 20)
                                        {
                                            strValorExtenso = strValorExtenso + (Right(strValorExtenso, 5).Trim() == "entos" ? " e " : " ")
                                            + fcn_Numero_Dezena0(Right(strDezena, 1));//corrigido

                                            bln_Unidade = true;
                                        }
                                        else
                                        {
                                            strValorExtenso = strValorExtenso + (Right(strValorExtenso, 5).Trim() == "entos" ? " e " : " ")
                                            + fcn_Numero_Dezena1(Left(strDezena, 1));//corrigido 

                                            bln_Unidade = false;
                                        }
                                        if (intContador == 7)
                                        {
                                            bln_Milhao = true;
                                        }
                                        else if (intContador == 4)
                                        {
                                            bln_Mil = true;
                                        }
                                    }
                                    break;
                                }
                            case 6: /******************/
                            case 3: //Unidade de Milhão* 
                            case 0: /******************/
                                {
                                    if (int.Parse(strNumero) > 0 && !bln_Unidade)
                                    {
                                        if ((Right(strValorExtenso, 5).Trim()) == "entos"
                                        || (Right(strValorExtenso, 3).Trim()) == "nte"
                                        || (Right(strValorExtenso, 3).Trim()) == "nta")
                                        {
                                            strValorExtenso = strValorExtenso + " e ";
                                        }
                                        else
                                        {
                                            strValorExtenso = strValorExtenso + " ";
                                        }
                                        strValorExtenso = strValorExtenso + fcn_Numero_Unidade(strNumero);
                                    }
                                    if (i == 6)
                                    {
                                        if (bln_Milhao || int.Parse(strNumero) > 0)
                                        {
                                            strValorExtenso = strValorExtenso + ((int.Parse(strNumero) == 1) && !bln_Unidade ? " Milhão" : " Milhões");
                                            strValorExtenso = strValorExtenso + ((int.Parse(strNumero) > 1000000) ? " " : " e");
                                            bln_Milhao = true;
                                        }
                                    }
                                    if (i == 3)
                                    {
                                        if (bln_Mil || int.Parse(strNumero) > 0)
                                        {
                                            strValorExtenso = strValorExtenso + " Mil";
                                            strValorExtenso = strValorExtenso + ((int.Parse(strNumero) > 1000) ? " " : " e");
                                            bln_Mil = true;
                                        }
                                    }
                                    if (i == 0)
                                    {
                                        if ((bln_Bilhao && !bln_Milhao && !bln_Mil
                                        && Right((dblValorInteiro.ToString().Trim()), 3) == "0")
                                        || (!bln_Bilhao && bln_Milhao && !bln_Mil
                                        && Right((dblValorInteiro.ToString().Trim()), 3) == "0"))
                                        {
                                            strValorExtenso = strValorExtenso + " e ";
                                        }
                                        strValorExtenso = strValorExtenso + ((Int64.Parse(dblValorInteiro.ToString())) > 1 ? " Reais" : " Real");
                                    }
                                    bln_Unidade = false;
                                    break;
                                }
                        }
                    }//
                }
                if (dblCentavos > 0)
                {

                    if (dblCentavos > 0 && dblCentavos < 0.1M)
                    {
                        strNumero = Right((Decimal.Round(dblCentavos, 2)).ToString().Trim(), 1);
                        strValorExtenso = strValorExtenso + ((dblCentavos > 0) ? " e " : " ")
                        + fcn_Numero_Unidade(strNumero) + ((dblCentavos > 0.01M) ? " Centavos" : " Centavo");
                    }
                    else if (dblCentavos > 0.1M && dblCentavos < 0.2M)
                    {
                        strNumero = Right(((Decimal.Round(dblCentavos, 2) - (decimal)0.1).ToString().Trim()), 1);
                        strValorExtenso = strValorExtenso + ((dblCentavos > 0) ? " " : " e ")
                        + fcn_Numero_Dezena0(strNumero) + " Centavos ";
                    }
                    else
                    {
                        strNumero = Right(dblCentavos.ToString().Trim(), 2);
                        strDezCentavo = Mid(dblCentavos.ToString().Trim(), 2, 1);

                        strValorExtenso = strValorExtenso + ((int.Parse(strNumero) > 0) ? " e " : " ");
                        strValorExtenso = strValorExtenso + fcn_Numero_Dezena1(Left(strDezCentavo, 1));

                        if ((dblCentavos.ToString().Trim().Length) > 2)
                        {
                            strNumero = Right((Decimal.Round(dblCentavos, 2)).ToString().Trim(), 1);
                            if (int.Parse(strNumero) > 0)
                            {
                                if (dblValorInteiro <= 0)
                                {
                                    if (Mid(strValorExtenso.Trim(), strValorExtenso.Trim().Length - 2, 1) == "e")
                                    {
                                        strValorExtenso = strValorExtenso + " e " + fcn_Numero_Unidade(strNumero);
                                    }
                                    else
                                    {
                                        strValorExtenso = strValorExtenso + " e " + fcn_Numero_Unidade(strNumero);
                                    }
                                }
                                else
                                {
                                    strValorExtenso = strValorExtenso + " e " + fcn_Numero_Unidade(strNumero);
                                }
                            }
                        }
                        strValorExtenso = strValorExtenso + " Centavos ";
                    }
                }
                if (dblValorInteiro < 1) strValorExtenso = Mid(strValorExtenso.Trim(), 2, strValorExtenso.Trim().Length - 2);
            }

            return strValorExtenso.Trim();
        }

        #region Funcões, Dezena,Centena, Unidade

        private static string fcn_Numero_Dezena0(string pstrDezena0)
        {
            //Vetor que irá conter o número por extenso 
            System.Collections.ArrayList array_Dezena0 = new System.Collections.ArrayList();

            array_Dezena0.Add("Onze");
            array_Dezena0.Add("Doze");
            array_Dezena0.Add("Treze");
            array_Dezena0.Add("Quatorze");
            array_Dezena0.Add("Quinze");
            array_Dezena0.Add("Dezesseis");
            array_Dezena0.Add("Dezessete");
            array_Dezena0.Add("Dezoito");
            array_Dezena0.Add("Dezenove");

            return array_Dezena0[((int.Parse(pstrDezena0)) - 1)].ToString();
        }
        private static string fcn_Numero_Dezena1(string pstrDezena1)
        {
            //Vetor que irá conter o número por extenso
            System.Collections.ArrayList array_Dezena1 = new System.Collections.ArrayList();

            array_Dezena1.Add("Dez");
            array_Dezena1.Add("Vinte");
            array_Dezena1.Add("Trinta");
            array_Dezena1.Add("Quarenta");
            array_Dezena1.Add("Cinquenta");
            array_Dezena1.Add("Sessenta");
            array_Dezena1.Add("Setenta");
            array_Dezena1.Add("Oitenta");
            array_Dezena1.Add("Noventa");

            return array_Dezena1[Int16.Parse(pstrDezena1) - 1].ToString();
        }
        private static string fcn_Numero_Centena(string pstrCentena)
        {
            //Vetor que irá conter o número por extenso
            System.Collections.ArrayList array_Centena = new System.Collections.ArrayList();

            array_Centena.Add("Cem");
            array_Centena.Add("Duzentos");
            array_Centena.Add("Trezentos");
            array_Centena.Add("Quatrocentos");
            array_Centena.Add("Quinhentos");
            array_Centena.Add("Seiscentos");
            array_Centena.Add("Setecentos");
            array_Centena.Add("Oitocentos");
            array_Centena.Add("Novecentos");

            return array_Centena[((int.Parse(pstrCentena)) - 1)].ToString();
        }
        private static string fcn_Numero_Unidade(string pstrUnidade)
        {
            //Vetor que irá conter o número por extenso
            System.Collections.ArrayList array_Unidade = new System.Collections.ArrayList();

            array_Unidade.Add("Um");
            array_Unidade.Add("Dois");
            array_Unidade.Add("Três");
            array_Unidade.Add("Quatro");
            array_Unidade.Add("Cinco");
            array_Unidade.Add("Seis");
            array_Unidade.Add("Sete");
            array_Unidade.Add("Oito");
            array_Unidade.Add("Nove");

            return array_Unidade[(int.Parse(pstrUnidade) - 1)].ToString();
        }

        #endregion

        #region Metodos de Compatibilização com VB6 - Left() Right() Mid()
        //Começa aqui os Métodos de Compatibilazação com VB 6 .........Left() Right() Mid()
        public static string Left(string param, int length)
        {
            //we start at 0 since we want to get the characters starting from the 
            //left and with the specified lenght and assign it to a variable
            if (param == "")
                return "";
            string result = param.Substring(0, length);
            //return the result of the operation 
            return result;
        }
        public static string Right(string param, int length)
        {
            //start at the index based on the lenght of the sting minus
            //the specified lenght and assign it a variable 
            if (param == "")
                return "";
            string result = param.Substring(param.Length - length, length);
            //return the result of the operation
            return result;
        }
        public static string Mid(string param, int startIndex, int length)
        {
            //start at the specified index in the string ang get N number of
            //characters depending on the lenght and assign it to a variable 
            string result = param.Substring(startIndex, length);
            //return the result of the operation
            return result;
        }
        public static string Mid(string param, int startIndex)
        {
            //start at the specified index and return all characters after it
            //and assign it to a variable
            string result = param.Substring(startIndex);
            //return the result of the operation 
            return result;
        }
        ////Acaba aqui os Métodos de Compatibilazação com VB 6 .........
        #endregion

        #endregion

        #region Converter CSV para DataSet

        public static System.Data.DataSet CsvToDataSet(string arquivoCSV, string PathFile)
        {

            string CSVFile = arquivoCSV.ToString();
            string PathCSV = PathFile.ToString();
            //Arquivo CSV
            string strFile = HttpContext.Current.Server.MapPath(PathCSV + CSVFile);
            //Separador do seu arquivo CSV 
            char separator = ';';
            //Se a primeira linha contém o nome das colunas
            bool isRowOneHeader = true;

            System.Data.DataTable csvDataTable = new System.Data.DataTable();
            String[] csvData = File.ReadAllLines(strFile);

            //Se o arquivo .csv não está vazio
            if (csvData.Length > 0)
            {
                String[] headings = csvData[0].Split(separator);
                int intRowIndex = 0;

                //Se a primeira linha contém o nome das colunas
                if (isRowOneHeader)
                {
                    for (int i = 0; i < headings.Length; i++)
                    {
                        //Adiciona colunas ao DataTable
                        csvDataTable.Columns.Add(headings[i].ToString());
                    }

                    intRowIndex++;
                }
                //Se a primeira linha não contém o nome das colunas, 
                //adiciona colunas como "Coluna1", "Coluna2", etc.
                else
                {
                    for (int i = 0; i < headings.Length; i++)
                    {
                        csvDataTable.Columns.Add("Coluna" + (i + 1).ToString());
                    }
                }

                //Popula o DataTable
                for (int i = intRowIndex; i < csvData.Length; i++)
                {
                    //Cria uma nova linha
                    System.Data.DataRow row = csvDataTable.NewRow();

                    for (int j = 0; j < headings.Length; j++)
                    {
                        //Adiciona os valores de cada coluna
                        row[j] = csvData[i].Split(separator)[j];
                    }

                    //Adiciona a linha ao DataTable
                    csvDataTable.Rows.Add(row);
                }
            }

            //Cria o DataSet e adiciona o DataTable nele
            System.Data.DataSet myDataSet = new System.Data.DataSet();
            myDataSet.Tables.Add(csvDataTable);

            return myDataSet;
        }

        #endregion
    }

    #endregion

    #region tratamento de arquivos e imagens

    /// <summary>
    /// Classe de manipulacão de arquivos : 8 Funcoes
    /// </summary>
    public class Arquivos
    {
        /// <summary>
        /// Define quais o tipos de arquivos, ou extenções de arquivos são permitido em um upload,
        /// passando-se como parâmetro o Arquivo, e o tipo de extensão.
        /// EX: " '.jpg', '.png' " -> separados por aspas simples ' ', ' '
        /// </summary>
        /// <param name="arquivo"></param>
        /// <param name="tipo"></param>
        /// <returns></returns>
        public static bool permitirExtensao(string arquivo, string tipo) // topo = " '.jpg', '.png' "
        {
            string extensao = System.IO.Path.GetExtension(arquivo).ToLower();

            tipo = tipo.Replace("\'", "\"");
            string[] permitidos = { tipo };
            for (int i = 0; 0 < permitidos.Length; i++)
            {
                if (String.Compare(extensao, permitidos[i]) == 0)
                {
                    return true;
                }
            }
            return false;
        }

        /// <summary>
        /// Le o conteudo de um arquivo.
        /// </summary>
        /// <param name="arquivo"></param>
        /// <returns></returns>
        public static string LerArquivo(Stream arquivo)
        {
            StreamReader arquiv = new StreamReader(arquivo, System.Text.Encoding.GetEncoding("ISO-8859-1"));
            return arquiv.ReadToEnd();
        }

        /// <summary>
        /// Cria um arquivo caso ele nao exista, recebendo os parametros:
        /// NomeDoArquivo : Define um nome ao arquivo + sua extensao como: .txt, .doc e etc. a ser criado.
        /// PathFisico : Define onde o arquivo será salvo.
        /// 
        /// </summary>
        /// <param name="NomeArquivo"></param>
        /// <param name="extensao"></param>
        /// <param name="PathFisico"></param>
        /// <param name="nomeArquivo"></param>
        /// <param name="Linhas"></param>
        /// <returns></returns>
        public string CreateAndRecordFiles(string NomeArquivo, string extensao, string PathFisico, string Linhas)
        {
            string Mensagem = "";
            string name = NomeArquivo.ToString();
            string arquivo = @" " + PathFisico + name + extensao + " ";

            FileInfo fileInfo = new FileInfo(arquivo);

            //Arquivo Existe?
            if (fileInfo.Exists)
            {
                //Abre um streamWriter no arquivo
                StreamWriter stream = new StreamWriter(arquivo);
                //Acrescenta linhas no arquivo
                stream.WriteLine(Linhas);
                for (int i = 1; i < Linhas.Length; i++)
                    stream.WriteLine(i.ToString());
                //Fecha o arquivo e stream
                stream.Close();

                //Retorna com sucesso a criação do arquivo
                Mensagem = "Arquivo " + NomeArquivo + " alterado com sucesso!";

                return Mensagem;
            }
            else
            {
                //Cria o arquivo caso o mesmo nao exista
                fileInfo.Create();

                //Abre um streamWriter no arquivo
                StreamWriter stream = new StreamWriter(arquivo);
                //Acrescenta linhas no arquivo
                stream.WriteLine(Linhas);
                for (int i = 1; i < Linhas.Length; i++)
                    stream.WriteLine(i.ToString());
                //Fecha o arquivo e stream
                stream.Close();

                //Retorna com sucesso a criação do arquivo
                Mensagem = "Arquivo " + NomeArquivo + " criado com sucesso!";

                return Mensagem;

            }

        }

        /// <summary>
        /// Faz um resize de imagem, passa-se como parametro a imagem, width e height. Retornando a imagem em um novo tamanho
        /// </summary>
        /// <param name="source"></param>
        /// <param name="width"></param>
        /// <param name="height"></param>
        /// <returns></returns>
        public static System.Drawing.Bitmap Resize(System.Drawing.Bitmap source, int width, int height)
        {
            System.Drawing.Bitmap resized = new System.Drawing.Bitmap(width, height);
            using (System.Drawing.Graphics g = System.Drawing.Graphics.FromImage((System.Drawing.Image)resized))
            {
                g.DrawImage(source, 0, 0, width, height);
            }
            return resized;
        }

        /// <summary>
        /// Faz um resize na imagem, passa-se os parametros:
        /// pathFisico1: destina-se o caminho de onde a imagem de origem esta.
        /// pathFisico2: destina-se o caminho de onde a imagem será salva apos o resize.
        /// arquivoOrigem: define o nome da imagem que deseja fazer o resize.
        /// arquivoDestino: define o nome do arquivo de destino que será salvo após o resize.
        /// width: define um tamanho em largura para o arquivo
        /// maxHeight: define o tamanho máximo em altura para o arquivo.
        /// resizeWide: define se a imagem será em tamanho ou tipo WideScreen, true ou false.
        /// </summary>
        /// <param name="pathFisico1"></param>
        /// <param name="pathFisico2"></param>
        /// <param name="arquivoOrigem"></param>
        /// <param name="arquivoDestino"></param>
        /// <param name="width"></param>
        /// <param name="maxHeight"></param>
        /// <param name="resizeWide"></param>
        /// <returns></returns>
        public static string ResizeImage(string pathFisico1, string pathFisico2, string arquivoOrigem, string arquivoDestino, int width, int maxHeight, bool resizeWide)
        {
            arquivoOrigem = pathFisico1 + arquivoOrigem;
            arquivoDestino = pathFisico2 + arquivoDestino;

            System.Drawing.Image originalImg = System.Drawing.Image.FromFile(arquivoOrigem);

            if (resizeWide && originalImg.Width <= width)
            {
                width = originalImg.Width;
            }

            int novaHeight = originalImg.Height * width / originalImg.Width;

            if (novaHeight > maxHeight)
            {
                width = originalImg.Width * maxHeight / originalImg.Height;
                novaHeight = maxHeight;
            }

            System.Drawing.Image novaImagem = originalImg.GetThumbnailImage(width, novaHeight, null, IntPtr.Zero);
            originalImg.Dispose();
            novaImagem.Save(arquivoDestino);

            return arquivoDestino;
        }

        /// <summary>
        /// Gera um Captcha dentro de um PageLoad em um webform vazio.
        /// Para usar, Crie um web form com o nome GerarCaptcha.aspx, e no codebehind chame a classe,
        /// Helpers.Arquivos.GerarCaptcha(int width, int height), e na pagina ou local onde quer que o captcha aparece,
        /// coloque um web server controle do tipo Image e atribua o ImageUrl="~/GerarCaptcha.aspx".
        /// EX: <asp:Image id="captchaImage" runat=server ImageUrl="~/GerarCaptcha.aspx" Height="50px" Width="150px" />
        /// Para usar o captcha no CodeBehind faca:
        /// 'Compare um campo TextBox com a Session["captcha"].ToString();
        /// </summary>
        /// <param name="width"></param>
        /// <param name="height"></param>
        public static void GerarCaptcha(int width, int height)
        {
            //Prepara os componentes de saida para desenho
            Bitmap bmp = new Bitmap(width, height);
            Graphics graph = Graphics.FromImage(bmp);

            //Limpa com cores locas..
            graph.Clear(Color.Aquamarine);
            graph.TextRenderingHint = System.Drawing.Text.TextRenderingHint.SystemDefault;
            //gera um random de letras e numeros
            string senhaCaptcha = "";
            Random rand = new Random();
            for (int x = 0; x < 6; x++)
                senhaCaptcha += (char)rand.Next(48, 122); //40 = zero 122 = z

            //grava na variavel de sessão
            HttpContext.Current.Session.Add("captcha", senhaCaptcha);

            //desenha na tela
            Font fonte = new Font("Calibri", 14, FontStyle.Italic);
            graph.DrawString(senhaCaptcha, fonte, Brushes.OliveDrab, 1, 1);

            //Manda pro rersponse
            HttpContext.Current.Response.ContentType = "image/gif";
            bmp.Save(HttpContext.Current.Response.OutputStream, ImageFormat.Gif);

            //Dispose
            graph.Dispose();
            fonte.Dispose();
            bmp.Dispose();
        }


    }

    #endregion

    #region Maps e Geografia

    /// <summary>
    /// Classe para ser usada com o google maps, fazendo o GeoCode reverso e Formatando a latitude e longitude
    /// </summary>
    public class CMaps
    {
        public string region = "";
        public static string Coordenada = "";

        public static Coordinate GetCoordinates(string region)
        {
            string Latitude = "";
            string Longitude = "";
            string FormattedAddress = "";
            string LocationType = "";

            // Envia o endereco para a url retornando uma resposta em XML 
            //http://maps.googleapis.com/maps/api/geocode/xml?address=1600+Amphitheatre+Parkway,+Mountain+View,+CA&sensor=true_or_false

            string uri = "http://maps.googleapis.com/maps/api/geocode/xml?address=" + region + "&sensor=true";

            System.Net.WebResponse response = null;
            try
            {
                System.Net.HttpWebRequest request = (System.Net.HttpWebRequest)System.Net.WebRequest.Create(uri);
                request.Method = "GET";
                response = request.GetResponse();
                if (response != null)
                {
                    System.Xml.XPath.XPathDocument document = new System.Xml.XPath.XPathDocument(response.GetResponseStream());
                    System.Xml.XPath.XPathNavigator navigator = document.CreateNavigator();

                    // get response status
                    System.Xml.XPath.XPathNodeIterator statusIterator = navigator.Select("/GeocodeResponse/status");
                    while (statusIterator.MoveNext())
                    {
                        if (statusIterator.Current.Value != "OK")
                        {
                            Console.WriteLine("Error: Response status = '" + statusIterator.Current.Value + "'");
                            break;
                        }
                    }
                    // GET RESULTS  
                    System.Xml.XPath.XPathNodeIterator resultIterator = navigator.Select("/GeocodeResponse/result");
                    while (resultIterator.MoveNext())
                    {


                        System.Xml.XPath.XPathNodeIterator formattedAddressIterator = resultIterator.Current.Select("formatted_address");
                        while (formattedAddressIterator.MoveNext())
                        {
                            FormattedAddress = formattedAddressIterator.Current.Value;
                        }

                        System.Xml.XPath.XPathNodeIterator geometryIterator = resultIterator.Current.Select("geometry");
                        while (geometryIterator.MoveNext())
                        {


                            System.Xml.XPath.XPathNodeIterator locationIterator = geometryIterator.Current.Select("location");
                            while (locationIterator.MoveNext())
                            {


                                System.Xml.XPath.XPathNodeIterator latIterator = locationIterator.Current.Select("lat");
                                while (latIterator.MoveNext())
                                {
                                    Latitude = latIterator.Current.Value;

                                }

                                System.Xml.XPath.XPathNodeIterator lngIterator = locationIterator.Current.Select("lng");
                                while (lngIterator.MoveNext())
                                {
                                    Longitude = lngIterator.Current.Value;

                                }
                            }

                            System.Xml.XPath.XPathNodeIterator locationTypeIterator = geometryIterator.Current.Select("location_type");
                            while (locationTypeIterator.MoveNext())
                            {
                                LocationType = locationTypeIterator.Current.Value;
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
            }
            finally
            {
                Console.WriteLine("Clean up");
                if (response != null)
                {
                    response.Close();
                    response = null;
                }
            }

            //Após extraido as infomações, retorna as mesma para o metodo Coordinate(Lat, Long), que formata a lat e long, no padrão exigido pelo google.
            return new Coordinate(Convert.ToDouble(Latitude), Convert.ToDouble(Longitude));
        }

        public struct Coordinate
        {

            private double lat;
            private double lng;

            public Coordinate(double latitude, double longitude)
            {
                lat = latitude;
                lng = longitude;
                //Coordenada = String.Format(@"{0:00\.0000000}", lat) + ", " + String.Format(@"{0:00\.0000000}", lng);
                Coordenada = Formatar.CoordinateLatLng(lat, lng);

            }

            public double Latitude { get { return lat; } set { lat = value; } }
            public double Longitude { get { return lng; } set { lng = value; } }

        }
    }

    #endregion

    #region Outros e Tratamento de URLs

    public class UrlPath
    {
        /// <summary>
        /// Retorna o caminho do servidor.EX: http://servidor.com
        /// </summary>
        /// <returns></returns>
        public static string Raiz()
        {
            return HttpContext.Current.Request.Url.GetLeftPart(UriPartial.Authority) + VirtualPathUtility.ToAbsolute("~/");
        }

        /// <summary>
        /// Criptografa uma queryString
        /// </summary>
        /// <param name="valor"></param>
        /// <returns></returns>
        public static string QueryStringEncript(string valor)
        {
            return Criptografia.Encrypt(valor);
        }

        /// <summary>
        /// Descriptografa uma queryString
        /// </summary>
        /// <param name="valor"></param>
        /// <returns></returns>
        public static string QueryStringDecrypt(string valor)
        {
            return Criptografia.Decrypt(valor);
        }
    }

    /// <summary>
    /// Funcção para Retornar NorFound e Validar URL Local : 2 funcoes
    /// </summary>
    public class Secure : HttpContextBase
    {

        public static string Unknown()
        {
            var NotFound = "Página não encontrada";

            return NotFound;
        }

        public bool ValidaUrlLocal(string Url)
        {
            if (Url == null || Url.Length == 0) return false;

            Uri absoluteUri;

            if (Uri.TryCreate(Url, UriKind.Absolute, out absoluteUri))
            {
                return String.Equals(this.Request.Url.Host, absoluteUri.Host, StringComparison.OrdinalIgnoreCase);
                //this.Request.Url.Host, absoluteUri.Host, StringComparison.OrdinalIgnoreCase);
            }
            else
            {
                bool isLocal = Url.StartsWith("http:", StringComparison.OrdinalIgnoreCase) &&
                               !Url.StartsWith("https:", StringComparison.OrdinalIgnoreCase) &&
                               Uri.IsWellFormedUriString(Url, UriKind.Relative);

                return isLocal;
            }
        }
    }

    /// <summary>
    /// Funcoes de Internet e Servidor : 2 funcoes
    /// </summary>
    public class Internet
    {
        /// <summary>
        /// Verifica se existe uma conexao com a internet, retornando um valor do tipo string;
        /// </summary>
        /// <returns></returns>
        public static string NetIsAvaliable()
        {
            if (System.Net.NetworkInformation.NetworkInterface.GetIsNetworkAvailable())
                return "Conexão com a internet ativa!";
            else
                return "Não há conexão com a internet Ativa!";
        }

        /// <summary>
        /// Faz um ping para ver se esta com conexao ativa no IP.
        /// USE: if(Core.Internet.doPing("192.168.0.1",250))  TextBox1.Text = "OK, Pingou"; else "Fora da rede!";
        /// </summary>
        /// <param name="IP"></param>
        /// <param name="Timeout"></param>
        /// <returns>Retorna o status do IP</returns>
        public static bool doPing(string IP, int Timeout)
        {
            System.Net.NetworkInformation.PingReply reply1 = new System.Net.NetworkInformation.Ping().Send(IP, Timeout); //Timeout em milisegundos
            return (reply1.Status == System.Net.NetworkInformation.IPStatus.Success);
        }
    }

    #endregion

}