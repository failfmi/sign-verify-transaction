using System;
using System.Linq;
using System.Text;
using Newtonsoft.Json;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Security;

namespace CSharpCryptography
{
    class SignVerify
    {
        static readonly X9ECParameters curve = SecNamedCurves.GetByName("secp256k1");
        private static readonly ECDomainParameters Domain = new ECDomainParameters(curve.Curve, curve.G, curve.N, curve.H);

        public static string BytesToHex(byte[] bytes)
        {
            return string.Concat(bytes.Select(b => b.ToString("x2")));
        }

        public byte[] GetBytes(string data)
        {
            byte[] bytes = Encoding.UTF8.GetBytes(data);
            return bytes;
        }

        private static string CalcRipeMD160(string text)
        {
            byte[] bytes = Encoding.UTF8.GetBytes(text);
            RipeMD160Digest digest = new RipeMD160Digest();
            digest.BlockUpdate(bytes, 0, bytes.Length);
            byte[] result = new byte[digest.GetDigestSize()];
            digest.DoFinal(result, 0);
            return BytesToHex(result);
        }

        private static byte[] CalcSHA256(string text)
        {
            byte[] bytes = Encoding.UTF8.GetBytes(text);
            Sha256Digest digest = new Sha256Digest();
            digest.BlockUpdate(bytes, 0, bytes.Length);
            byte[] result = new byte[digest.GetDigestSize()];
            digest.DoFinal(result, 0);
            return result;
        }

        public static AsymmetricCipherKeyPair GenerateRandomKeys(int keySize = 256)
        {
            ECKeyPairGenerator gen = new ECKeyPairGenerator();
            SecureRandom secureRandom = new SecureRandom();
            KeyGenerationParameters keyGenParam =
                new KeyGenerationParameters(secureRandom, keySize);
            gen.Init(keyGenParam);
            return gen.GenerateKeyPair();
        }

        public static ECPublicKeyParameters ToPublicKey(string privateKey)
        {
            BigInteger d = new BigInteger(privateKey, 16);
            var q = Domain.G.Multiply(d);

            var publicParams = new ECPublicKeyParameters(q, Domain);

            return publicParams;
        }

        public static string EncodeECPointHexCompressed(ECPoint point)
        {
            BigInteger x = point.XCoord.ToBigInteger();
            return x.ToString(16) + Convert.ToInt32(!x.TestBit(0));
        }

        private static void RandomPrivateKeyToAddress()
        {
            Console.WriteLine("Random private key --> public key --> address");
            Console.WriteLine("---------------------------------------------");

            var keyPair = GenerateRandomKeys();

            BigInteger privateKey = ((ECPrivateKeyParameters)keyPair.Private).D;
            Console.WriteLine("Private key (hex): " + privateKey.ToString(16));
            Console.WriteLine("Private key: " + privateKey.ToString(10));

            ECPoint pubKey = ((ECPublicKeyParameters)keyPair.Public).Q;
            Console.WriteLine("Public key: ({0}, {1})",
                pubKey.XCoord.ToBigInteger().ToString(10),
                pubKey.YCoord.ToBigInteger().ToString(10));

            string pubKeyCompressed = EncodeECPointHexCompressed(pubKey);
            Console.WriteLine("Public key (compressed): " + pubKeyCompressed);

            string addr = CalcRipeMD160(pubKeyCompressed);
            Console.WriteLine("Blockchain address: " + addr);
        }

        public static ECPoint GetPublicKeyFromPrivateKey(BigInteger privKey)
        {
            ECPoint pubKey = curve.G.Multiply(privKey).Normalize();
            return pubKey;
        }

        private static void ExistingPrivateKeyToAddress(string privKeyHex)
        {
            Console.WriteLine("Existing private key --> public key --> address");
            Console.WriteLine("-----------------------------------------------");

            BigInteger privateKey = new BigInteger(privKeyHex, 16);
            Console.WriteLine("Private key (hex): " + privateKey.ToString(16));
            Console.WriteLine("Private key: " + privateKey.ToString(10));

            ECPoint pubKey = GetPublicKeyFromPrivateKey(privateKey);
            Console.WriteLine("Public key: ({0}, {1})",
                pubKey.XCoord.ToBigInteger().ToString(10),
                pubKey.YCoord.ToBigInteger().ToString(10));

            string pubKeyCompressed = EncodeECPointHexCompressed(pubKey);
            Console.WriteLine("Public key (compressed): " + pubKeyCompressed);

            string addr = CalcRipeMD160(pubKeyCompressed);
            Console.WriteLine("Blockchain address: " + addr);
        }

        private static BigInteger[] SignData(BigInteger privateKey, byte[] data)
        {
            ECPrivateKeyParameters keyParameters = new ECPrivateKeyParameters(privateKey, Domain);
            IDsaKCalculator kCalculator = new HMacDsaKCalculator(new Sha256Digest());
            ECDsaSigner signer = new ECDsaSigner(kCalculator);
            signer.Init(true, keyParameters);
            BigInteger[] signature = signer.GenerateSignature(data);

            return signature;
        }

        //public static byte[] SignData(string msg, BigInteger privateKeyInt)
        //{ 
        //    ECPrivateKeyParameters privateKeyParameters = new ECPrivateKeyParameters(privateKeyInt, Domain);
        //    byte[] msgBytes = Encoding.UTF8.GetBytes(msg);

        //    ISigner signer = SignerUtilities.GetSigner("SHA-256withECDSA");
        //    signer.Init(true, privateKeyParameters);
        //    signer.BlockUpdate(msgBytes, 0, msgBytes.Length);
        //    byte[] sigBytes = signer.GenerateSignature();

        //    return sigBytes;
        //}

        public static bool VerifySignature(ECPublicKeyParameters pubKey, BigInteger[] signature, byte[] msg)
        {
            IDsaKCalculator kCalculator = new HMacDsaKCalculator(new Sha256Digest());
            ECDsaSigner signer = new ECDsaSigner(kCalculator);
            signer.Init(false, pubKey);

            return signer.VerifySignature(msg, signature[0], signature[1]);
        }

        //public static bool VerifySignature(string privateKey, byte[] signature, string msg)
        //{
        //    ECPublicKeyParameters pubKey = ToPublicKey(privateKey);
        //    byte[] msgBytes = Encoding.UTF8.GetBytes(msg);

        //    ISigner signer = SignerUtilities.GetSigner("SHA-256withECDSA");
        //    signer.Init(false, pubKey);
        //    signer.BlockUpdate(msgBytes, 0, msgBytes.Length);

        //    return signer.VerifySignature(signature);
        //}

        private static void SignAndVerifyTransaction(string recipientAddress, int value,
            int fee, string iso8601datetime, string senderPrivKeyHex)
        {
            Console.WriteLine("Generate and sign a transaction");
            Console.WriteLine("-------------------------------");

            Console.WriteLine("Sender private key:", senderPrivKeyHex);
            BigInteger privateKey = new BigInteger(senderPrivKeyHex, 16);

            ECPoint pubKey = GetPublicKeyFromPrivateKey(privateKey);
            string senderPubKeyCompressed = EncodeECPointHexCompressed(pubKey);
            Console.WriteLine("Public key (compressed): " + senderPubKeyCompressed);

            string senderAddress = CalcRipeMD160(senderPubKeyCompressed);
            Console.WriteLine("Blockchain address: " + senderAddress);

            var tran = new
            {
                from = senderAddress,
                to = recipientAddress,
                senderPubKey = senderPubKeyCompressed,
                value,
                fee,
                dateCreated = iso8601datetime,
            };
            string tranJson = JsonConvert.SerializeObject(tran);
            Console.WriteLine("Transaction (JSON): {0}", tranJson);

            byte[] tranHash = CalcSHA256(tranJson);
            Console.WriteLine("Transaction hash(sha256): {0}", BytesToHex(tranHash));

            BigInteger[] tranSignature = SignData(privateKey, tranHash);
            Console.WriteLine("Transaction signature: [{0}, {1}]", tranSignature[0].ToString(16), tranSignature[1].ToString(16));

            var tranSigned = new
            {
                from = senderAddress,
                to = recipientAddress,
                senderPubKey = senderPubKeyCompressed,
                value,
                fee,
                dateCreated = iso8601datetime,
                senderSignature = new[]
                {
                    tranSignature[0].ToString(16),
                    tranSignature[1].ToString(16)
                }
            };

            string signedTranJson = JsonConvert.SerializeObject(tranSigned, Formatting.Indented);
            Console.WriteLine("Signed transaction (JSON):");
            Console.WriteLine(signedTranJson);

            // Verify Transaction
            ECPublicKeyParameters ecPubKey = ToPublicKey(senderPrivKeyHex);
            bool isVerified = VerifySignature(ecPubKey, tranSignature, tranHash);
            Console.WriteLine("Is the signature: valid ? - " + isVerified);
        }

        static void Main()
        {
            RandomPrivateKeyToAddress();

            ExistingPrivateKeyToAddress("7e4670ae70c98d24f3662c172dc510a085578b9ccc717e6c2f4e547edd960a34");

            SignAndVerifyTransaction(
                recipientAddress: "f51362b7351ef62253a227a77751ad9b2302f911",
                value: 25000,
                fee: 10,
                iso8601datetime: "2018-02-10T17:53:48.972Z",
                senderPrivKeyHex: "7e4670ae70c98d24f3662c172dc510a085578b9ccc717e6c2f4e547edd960a34"
            );
        }
    }
}