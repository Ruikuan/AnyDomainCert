// See https://aka.ms/new-console-template for more information
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

using var rsa = RSA.Create();
X500DistinguishedNameBuilder dnBuilder = new X500DistinguishedNameBuilder();
dnBuilder.AddCommonName("hejicho Test Environment Certificate Root");
CertificateRequest request = new CertificateRequest(dnBuilder.Build(), rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));
var rootCert = request.CreateSelfSigned(DateTimeOffset.Now, DateTimeOffset.Now.AddYears(20));
//var rootCertWithKey = rootCert.CopyWithPrivateKey(rsa);
var certPem = rootCert.ExportCertificatePem();
File.WriteAllText("root.pem", certPem);
var keyPem = rootCert.GetRSAPrivateKey()!.ExportRSAPrivateKeyPem();
File.WriteAllText("key.pem", keyPem);
File.WriteAllBytes("root.cer", rootCert.Export(X509ContentType.Cert));
File.WriteAllBytes("root.pfx", rootCert.Export(X509ContentType.Pfx));