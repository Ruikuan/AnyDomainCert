using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

ConcurrentDictionary<string, X509Certificate2> _certificates = new ConcurrentDictionary<string, X509Certificate2>();

var rootCertPath = Path.Combine("../RootCert", "root.pem");
var rootKeyPath = Path.Combine("../RootCert", "key.pem");
var rootCert = X509Certificate2.CreateFromPemFile(rootCertPath, rootKeyPath); // initialize the root certificate

var builder = WebApplication.CreateBuilder(args);

builder.WebHost.ConfigureKestrel(options =>
{
    options.ConfigureHttpsDefaults(httpsOptions =>
    {
        httpsOptions.ServerCertificateSelector = (context, subjectName) =>
        {
            var subjectCert = _certificates.GetOrAdd(subjectName!, (domain) => 
            { 
                X500DistinguishedNameBuilder dnBuilder = new X500DistinguishedNameBuilder();
                dnBuilder.AddCommonName(domain!); // add cn=domain to the distinguished name
                
                using var rsa = RSA.Create();

                CertificateRequest request = new CertificateRequest(dnBuilder.Build(), rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false)); // end entity
                request.CertificateExtensions.Add(new X509KeyUsageExtension(
                        X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.NonRepudiation | X509KeyUsageFlags.KeyEncipherment,
                        false));

                request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
                        new OidCollection
                        {
                            new Oid("1.3.6.1.5.5.7.3.1"), // service authentication
                            new Oid("1.3.6.1.5.5.7.3.2")  // client authentication
                        },
                        true));
                request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false)); // subject key identifier

                SubjectAlternativeNameBuilder sanBuilder = new SubjectAlternativeNameBuilder(); // subject alternative name
                sanBuilder.AddDnsName(domain!);
                request.CertificateExtensions.Add(sanBuilder.Build());

                Span<byte> bytes = stackalloc byte[4]; // serial number
                Random.Shared.NextBytes(bytes);
                using var cert = request.Create(rootCert, DateTimeOffset.Now.AddMinutes(-1), DateTimeOffset.Now.AddYears(1), bytes); // sign the certificate
                using var certWithKey = cert.CopyWithPrivateKey(rsa); // if we return certWithKey directly, it won't work.
                
                // we have to do this trick to workaround SSLStream doesn't support ephemeral keys on Windows.
                var domainCert = new X509Certificate2(certWithKey.Export(X509ContentType.Pfx)); // don't know why have to use this method to get cert working.
                
                return domainCert;

            });

            return subjectCert;
        };
    });
});

var app = builder.Build();

app.MapGet("/", () => "Hello World!");

app.Run();
