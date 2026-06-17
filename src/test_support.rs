use rsa::RsaPrivateKey;
use std::fs;
use std::path::PathBuf;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_ID: AtomicU64 = AtomicU64::new(0);

static TEST_RSA_KEY: OnceLock<RsaPrivateKey> = OnceLock::new();

pub fn test_rsa_key() -> &'static RsaPrivateKey {
    TEST_RSA_KEY.get_or_init(|| {
        let mut rng = rand::thread_rng();
        RsaPrivateKey::new(&mut rng, 1024).unwrap()
    })
}

pub struct TlsFixture {
    pub cert: PathBuf,
    pub key: PathBuf,
}

impl Default for TlsFixture {
    fn default() -> Self {
        Self::new()
    }
}

impl TlsFixture {
    pub fn new() -> Self {
        let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        let base =
            std::env::temp_dir().join(format!("xminecraft-test-{}-{id}", std::process::id()));
        fs::create_dir_all(&base).expect("create TLS fixture temp directory");

        let cert = base.join("cert.pem");
        let key = base.join("key.pem");
        fs::write(&cert, TEST_CERT).expect("write TLS test certificate");
        fs::write(&key, TEST_KEY).expect("write TLS test private key");

        Self { cert, key }
    }
}

impl Drop for TlsFixture {
    fn drop(&mut self) {
        if let Some(parent) = self.cert.parent() {
            let _ = fs::remove_dir_all(parent);
        }
    }
}

const TEST_CERT: &str = r#"-----BEGIN CERTIFICATE-----
MIIDQzCCAiugAwIBAgIUFi0dAnsrVjrKeseehHhd4oehi8AwDQYJKoZIhvcNAQEL
BQAwFDESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTI2MDQyOTE4MTgxOFoXDTM2MDQy
NjE4MTgxOFowFDESMBAGA1UEAwwJbG9jYWxob3N0MIIBIjANBgkqhkiG9w0BAQEF
AAOCAQ8AMIIBCgKCAQEA3h9tmDZrTB1SZZLDAO4PJyqOUnlaxRx0v6vBdLU0mKYg
l52kK1FZvqWW0QqGwCnKJnc+DMIY/MMzyEZa1bO2nF8PNvpkIbZkDdCfsuaJsmvn
n4pAPDJUnKLjjLVs/EKuocDMIrik5KW5vE5RkCVhFI6VOWM+zn9OC22uQq4eff/4
yXDroph8xirbzXJK8c4MAzIGJ4Qed6Bepd+Hfh8gvBthjTzeBYSOzfICgXQLAsul
YrXv4OYeCUPgk3qCLEun+FZEP2AoAppMzanJi59iSaKhvyjkU5bvbsn6ZxPHRFvh
J6d+atGkjmVoWvnh4REl8Vk3k7y/fxC3Xz/7UEJZQwIDAQABo4GMMIGJMB0GA1Ud
DgQWBBQM+ytwp86v7WCXeIQC8SpKRvDUqTAfBgNVHSMEGDAWgBQM+ytwp86v7WCX
eIQC8SpKRvDUqTAUBgNVHREEDTALgglsb2NhbGhvc3QwDAYDVR0TAQH/BAIwADAO
BgNVHQ8BAf8EBAMCBaAwEwYDVR0lBAwwCgYIKwYBBQUHAwEwDQYJKoZIhvcNAQEL
BQADggEBAA/DySi5Vr1XvLKzKQxmJs2FioQGfEJosyjreg8TwT1R/QtvXyPCZXwV
1Q+iOz9+9LDmr50bLryoiEVcVCIGyupyh300M29UerStvwK5r2ojyMbrXw8VTCzs
u7Nw8ajFNlWoUkrU6ao/4nFHLBCEdWmoCA0QPn/0u+UJORkAKKsTbGPeEZBBBnZR
l75XJS+2ePPDPRcHL9ZFaNpeZnQcQGWVufxayfMfO/xQhF9DFrycRaQua3YTdMCL
MPJBELN+Hzy3syx3s+Q3ELKzfMyiL8jiyKtmMi25cm2QH8R1+8yDyvzhM8DMFGDT
BMDvPpSiX8TD/ifbsds9Jm9u2HK7ppQ=
-----END CERTIFICATE-----
"#;

const TEST_KEY: &str = r#"-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDeH22YNmtMHVJl
ksMA7g8nKo5SeVrFHHS/q8F0tTSYpiCXnaQrUVm+pZbRCobAKcomdz4Mwhj8wzPI
RlrVs7acXw82+mQhtmQN0J+y5omya+efikA8MlScouOMtWz8Qq6hwMwiuKTkpbm8
TlGQJWEUjpU5Yz7Of04Lba5Crh59//jJcOuimHzGKtvNckrxzgwDMgYnhB53oF6l
34d+HyC8G2GNPN4FhI7N8gKBdAsCy6Vite/g5h4JQ+CTeoIsS6f4VkQ/YCgCmkzN
qcmLn2JJoqG/KORTlu9uyfpnE8dEW+Enp35q0aSOZWha+eHhESXxWTeTvL9/ELdf
P/tQQllDAgMBAAECggEAZTGKO1snfNCq9i1re6P48U348ufoi35QTfYQt3vKT3T3
yjr+TOHN8gX8dJXIGAmx195hPWy794Nytt4eiddK7Wh9RP3D2nv+jzCpYNaYitmP
92YDp6kCVS38XuFUmoRCjNyJ45OdQ7GgsYI4tGPjG3ttzmxBc9AZnSlFx4kNyTaY
ODcu3uNKKLKE7X4CStLStPnu4XHqqZcyG0OmXuwBn3ynVlhPBUHEZPObClfkpF/2
pf+V+1NoImy0KRwj4SxvRtiWkpDDdy5z6LGDPq7wztp4tW+FhmClAKDMai/s1Ww2
RQ1tHE8Aoe3oXEGMhepc1R3PlD2ur6nbNGi6drJdWQKBgQDv/19dF8MSmmlttkwb
U6FYf/Z4Ykc0EQIdNEnrKQ4H6lVWXPb3+7DSVIcTz82Us9sFG4Iqa7NbKdSdoeMv
OC1HrPC4sDhEloLXM6nztQcAYpdh0eoNUVLkyc5HDPRlWmcqMXjHRPbSKIMXovQM
/mC9Gj5F/HSN+Xq6pIJDufn9hwKBgQDs7vFZ8pJSOSjqUmxVWrhpz3xx0Lh13U/m
CepybN2UFiaH3bcOy5jrkPQyZ6WYpU+wJjlNRiGTFxdWKy5z+o4g4sixk250LCMp
kqXMUbgesx29TK7WIpkABvq/nP+bNloHthNliES9UInIv2oeC5Jm6C32wsBABJCw
gtZ9NdDVZQKBgQDrc/bzNeTD04mrgTWZearJUIFWCdUhV65jSHFcrKJ/UX73g60o
DV2kfBkpbq2aPfmaQSqqw47q2VcmbzSbltmVgC2KhBgv8hnbV2xdFDUSQ6eQ6Ihf
GHHi07n0Ktl6tf6QfointxkPhX9XKR+Vv9rYq2586vjOcPvfMJY8K7D+8QKBgG+V
xOMYw+KneuaIdO7p7+odRr2PkCAqX6O2Tc0gCmbg27qnJ7x3FIj01p0ahTnTuSj7
h4cmHU/Z0yrI4XLLsL46MEy5Y46g7tp4b08/uVf0AXCSudCtsKL7poIxnYvq2BHD
pXTu7Xi/gnSh+Yc26fc/J86MP+CmhcIrjHqhqr2lAoGBAK8uvPR8CQoTjSaOAaD1
Fm5/8VvBaWx5NfBfmG2SB6ohe3rVYynlegPSCwJGu/Gx9haBiSEeQPSFeK9o4dUM
ziu+OQ1lATUJEZY/bTtNgSCvrclBzC4BGQndxlQZYvf0iMfTkLhIHi1okEbyBVAZ
QGPJJdjO+1OA73cBhSg0RaE0
-----END PRIVATE KEY-----
"#;
