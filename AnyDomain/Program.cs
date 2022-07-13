using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

ConcurrentDictionary<string, Lazy<X509Certificate2>> _certificates = new ConcurrentDictionary<string, Lazy<X509Certificate2>>();

var builder = WebApplication.CreateBuilder(args);

builder.WebHost.ConfigureKestrel(options =>
{
    options.ConfigureHttpsDefaults(httpsOptions =>
    {
        httpsOptions.ServerCertificateSelector = (context, subjectName) =>
        {
            Console.WriteLine(subjectName);
            try
            {
                return _certificates.GetOrAdd(subjectName!, (domain) => new Lazy<X509Certificate2>(()=>
                { 

                    var rootCertPath = Path.Combine("../RootCert", "root.pem");
                    var rootKeyPath = Path.Combine("../RootCert", "key.pem");
                    var rootCert = X509Certificate2.CreateFromPemFile(rootCertPath, rootKeyPath);

                    X500DistinguishedNameBuilder dnBuilder = new X500DistinguishedNameBuilder();
                    dnBuilder.AddCommonName(domain!);
                    
                    using var rsa = RSA.Create();

                    CertificateRequest request = new CertificateRequest(dnBuilder.Build(), rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                    request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));
                    request.CertificateExtensions.Add(new X509KeyUsageExtension(
                            X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.NonRepudiation | X509KeyUsageFlags.KeyEncipherment,
                            false));

                    request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
                            new OidCollection
                            {
                                new Oid("1.3.6.1.5.5.7.3.1"),
                                new Oid("1.3.6.1.5.5.7.3.2")
                            },
                            true));
                    request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));

                    SubjectAlternativeNameBuilder sanBuilder = new SubjectAlternativeNameBuilder();
                    sanBuilder.AddDnsName(domain!);
                    request.CertificateExtensions.Add(sanBuilder.Build());

                    Span<byte> bytes = stackalloc byte[4];
                    Random.Shared.NextBytes(bytes);
                    var cert = request.Create(rootCert, DateTimeOffset.Now, DateTimeOffset.Now.AddYears(1), bytes);
                    var certWithKey = cert.CopyWithPrivateKey(rsa);
                    File.WriteAllBytes($"{domain}.cer", certWithKey.Export(X509ContentType.Cert));
                    File.WriteAllBytes($"{domain}.pfx", certWithKey.Export(X509ContentType.Pfx));
                    return certWithKey;
                })).Value;
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                throw;
            }
        };
    });
});

var app = builder.Build();

app.MapGet("/", () => "Hello World!");

app.Run();
