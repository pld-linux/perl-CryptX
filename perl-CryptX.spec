#
# Conditional build:
%bcond_without	tests		# do not perform "make test"
#
%define	pnam	CryptX
Summary:	CryptX - cryptographic toolkit (self-contained, no external libraries needed)
Summary(pl.UTF-8):	CryptX - zestaw narządzi kryptograficznych (samowystarczalny, nie wymaga zewnętrznych bibliotek)
Name:		perl-CryptX
Version:	0.074
Release:	3
# same as perl
License:	GPL v1+ or Artistic
Group:		Development/Languages/Perl
Source0:	http://cpan.metacpan.org/authors/id/M/MI/MIK/%{pnam}-%{version}.tar.gz
# Source0-md5:	c937ce9d03f8efa9639600521a704ce7
URL:		http://search.cpan.org/dist/CryptX/
BuildRequires:	perl-devel >= 1:5.8.0
BuildRequires:	rpm-perlprov >= 4.1-13
BuildRoot:	%{tmpdir}/%{name}-%{version}-root-%(id -u -n)

%description
Cryptography in CryptX is based on https://github.com/libtom/libtomcrypt

Available modules:
- Symmetric ciphers - see Crypt::Cipher
- Block cipher modes
- Stream ciphers
- Authenticated encryption modes
- Hash Functions - see Crypt::Digest
- Checksums
- Message Authentication Codes
- Public key cryptography
- Cryptographically secure random number generators - see Crypt::PRNG
- Key derivation functions - PBKDF1, PBKDF2 and HKDF
- Other handy functions related to cryptography

%prep
%setup -q -n %{pnam}-%{version}

%build
%{__perl} Makefile.PL \
	INSTALLDIRS=vendor

%{__make}

%{?with_tests:%{__make} test}

%install
rm -rf $RPM_BUILD_ROOT

%{__make} install \
	DESTDIR=$RPM_BUILD_ROOT

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(644,root,root,755)
%doc Changes README.md
%{perl_vendorarch}/Crypt/AuthEnc/OCB.pm
%{perl_vendorarch}/Crypt/AuthEnc/CCM.pm
%{perl_vendorarch}/Crypt/AuthEnc/ChaCha20Poly1305.pm
%{perl_vendorarch}/Crypt/AuthEnc/GCM.pm
%{perl_vendorarch}/Crypt/AuthEnc/EAX.pm
%{perl_vendorarch}/Crypt/Checksum/CRC32.pm
%{perl_vendorarch}/Crypt/Checksum/Adler32.pm
%{perl_vendorarch}/Crypt/Cipher/Anubis.pm
%{perl_vendorarch}/Crypt/Cipher/KASUMI.pm
%{perl_vendorarch}/Crypt/Cipher/RC6.pm
%{perl_vendorarch}/Crypt/Cipher/DES.pm
%{perl_vendorarch}/Crypt/Cipher/XTEA.pm
%{perl_vendorarch}/Crypt/Cipher/CAST5.pm
%{perl_vendorarch}/Crypt/Cipher/MULTI2.pm
%{perl_vendorarch}/Crypt/Cipher/Serpent.pm
%{perl_vendorarch}/Crypt/Cipher/DES_EDE.pm
%{perl_vendorarch}/Crypt/Cipher/IDEA.pm
%{perl_vendorarch}/Crypt/Cipher/SAFER_K128.pm
%{perl_vendorarch}/Crypt/Cipher/SAFER_SK128.pm
%{perl_vendorarch}/Crypt/Cipher/RC5.pm
%{perl_vendorarch}/Crypt/Cipher/SAFER_K64.pm
%{perl_vendorarch}/Crypt/Cipher/Camellia.pm
%{perl_vendorarch}/Crypt/Cipher/Twofish.pm
%{perl_vendorarch}/Crypt/Cipher/Khazad.pm
%{perl_vendorarch}/Crypt/Cipher/Blowfish.pm
%{perl_vendorarch}/Crypt/Cipher/SEED.pm
%{perl_vendorarch}/Crypt/Cipher/Skipjack.pm
%{perl_vendorarch}/Crypt/Cipher/SAFERP.pm
%{perl_vendorarch}/Crypt/Cipher/RC2.pm
%{perl_vendorarch}/Crypt/Cipher/SAFER_SK64.pm
%{perl_vendorarch}/Crypt/Cipher/Noekeon.pm
%{perl_vendorarch}/Crypt/Cipher/AES.pm
%{perl_vendorarch}/Crypt/Digest/BLAKE2b_384.pm
%{perl_vendorarch}/Crypt/Digest/BLAKE2b_512.pm
%{perl_vendorarch}/Crypt/Digest/BLAKE2b_256.pm
%{perl_vendorarch}/Crypt/Digest/BLAKE2b_160.pm
%{perl_vendorarch}/Crypt/Digest/BLAKE2s_128.pm
%{perl_vendorarch}/Crypt/Digest/RIPEMD256.pm
%{perl_vendorarch}/Crypt/Digest/BLAKE2s_224.pm
%{perl_vendorarch}/Crypt/Digest/Whirlpool.pm
%{perl_vendorarch}/Crypt/Digest/SHA224.pm
%{perl_vendorarch}/Crypt/Digest/RIPEMD128.pm
%{perl_vendorarch}/Crypt/Digest/MD4.pm
%{perl_vendorarch}/Crypt/Digest/Keccak224.pm
%{perl_vendorarch}/Crypt/Digest/CHAES.pm
%{perl_vendorarch}/Crypt/Digest/SHA512.pm
%{perl_vendorarch}/Crypt/Digest/BLAKE2s_256.pm
%{perl_vendorarch}/Crypt/Digest/BLAKE2s_160.pm
%{perl_vendorarch}/Crypt/Digest/RIPEMD160.pm
%{perl_vendorarch}/Crypt/Digest/SHAKE.pm
%{perl_vendorarch}/Crypt/Digest/MD5.pm
%{perl_vendorarch}/Crypt/Digest/SHA384.pm
%{perl_vendorarch}/Crypt/Digest/SHA512_224.pm
%{perl_vendorarch}/Crypt/Digest/SHA1.pm
%{perl_vendorarch}/Crypt/Digest/Tiger192.pm
%{perl_vendorarch}/Crypt/Digest/SHA3_512.pm
%{perl_vendorarch}/Crypt/Digest/Keccak384.pm
%{perl_vendorarch}/Crypt/Digest/SHA512_256.pm
%{perl_vendorarch}/Crypt/Digest/SHA3_224.pm
%{perl_vendorarch}/Crypt/Digest/SHA3_384.pm
%{perl_vendorarch}/Crypt/Digest/SHA3_256.pm
%{perl_vendorarch}/Crypt/Digest/SHA256.pm
%{perl_vendorarch}/Crypt/Digest/MD2.pm
%{perl_vendorarch}/Crypt/Digest/Keccak256.pm
%{perl_vendorarch}/Crypt/Digest/RIPEMD320.pm
%{perl_vendorarch}/Crypt/Digest/Keccak512.pm
%{perl_vendorarch}/Crypt/Mac/HMAC.pm
%{perl_vendorarch}/Crypt/Mac/Poly1305.pm
%{perl_vendorarch}/Crypt/Mac/F9.pm
%{perl_vendorarch}/Crypt/Mac/BLAKE2b.pm
%{perl_vendorarch}/Crypt/Mac/Pelican.pm
%{perl_vendorarch}/Crypt/Mac/PMAC.pm
%{perl_vendorarch}/Crypt/Mac/OMAC.pm
%{perl_vendorarch}/Crypt/Mac/BLAKE2s.pm
%{perl_vendorarch}/Crypt/Mac/XCBC.pm
%{perl_vendorarch}/Crypt/Mode/ECB.pm
%{perl_vendorarch}/Crypt/Mode/CTR.pm
%{perl_vendorarch}/Crypt/Mode/CFB.pm
%{perl_vendorarch}/Crypt/Mode/CBC.pm
%{perl_vendorarch}/Crypt/Mode/OFB.pm
%{perl_vendorarch}/Crypt/PK/RSA.pm
%{perl_vendorarch}/Crypt/PK/DH.pm
%{perl_vendorarch}/Crypt/PK/DSA.pm
%{perl_vendorarch}/Crypt/PK/ECC.pm
%{perl_vendorarch}/Crypt/PK/Ed25519.pm
%{perl_vendorarch}/Crypt/PK/X25519.pm
%{perl_vendorarch}/Crypt/PRNG/Sober128.pm
%{perl_vendorarch}/Crypt/PRNG/ChaCha20.pm
%{perl_vendorarch}/Crypt/PRNG/RC4.pm
%{perl_vendorarch}/Crypt/PRNG/Yarrow.pm
%{perl_vendorarch}/Crypt/PRNG/Fortuna.pm
%{perl_vendorarch}/Crypt/Stream/Salsa20.pm
%{perl_vendorarch}/Crypt/Stream/Sosemanuk.pm
%{perl_vendorarch}/Crypt/Stream/ChaCha.pm
%{perl_vendorarch}/Crypt/Stream/RC4.pm
%{perl_vendorarch}/Crypt/Stream/Sober128.pm
%{perl_vendorarch}/Crypt/Stream/Rabbit.pm
%{perl_vendorarch}/Crypt/Cipher.pm
%{perl_vendorarch}/Crypt/AuthEnc.pm
%{perl_vendorarch}/Crypt/Checksum.pm
%{perl_vendorarch}/Crypt/Digest.pm
%{perl_vendorarch}/Crypt/KeyDerivation.pm
%{perl_vendorarch}/Crypt/Mac.pm
%{perl_vendorarch}/Crypt/PK.pm
%{perl_vendorarch}/Crypt/Mode.pm
%{perl_vendorarch}/Crypt/Misc.pm
%{perl_vendorarch}/Crypt/PRNG.pm
%{perl_vendorarch}/Math/BigInt/LTM.pm
%{perl_vendorarch}/CryptX.pm
%{perl_vendorarch}/auto/CryptX
%{_mandir}/man3/Crypt::AuthEnc.3pm.*
%{_mandir}/man3/Crypt::AuthEnc::CCM.3pm.*
%{_mandir}/man3/Crypt::AuthEnc::ChaCha20Poly1305.3pm.*
%{_mandir}/man3/Crypt::AuthEnc::EAX.3pm.*
%{_mandir}/man3/Crypt::AuthEnc::GCM.3pm.*
%{_mandir}/man3/Crypt::AuthEnc::OCB.3pm.*
%{_mandir}/man3/Crypt::Checksum.3pm.*
%{_mandir}/man3/Crypt::Checksum::Adler32.3pm.*
%{_mandir}/man3/Crypt::Checksum::CRC32.3pm.*
%{_mandir}/man3/Crypt::Cipher.3pm.*
%{_mandir}/man3/Crypt::Cipher::AES.3pm.*
%{_mandir}/man3/Crypt::Cipher::Anubis.3pm.*
%{_mandir}/man3/Crypt::Cipher::Blowfish.3pm.*
%{_mandir}/man3/Crypt::Cipher::CAST5.3pm.*
%{_mandir}/man3/Crypt::Cipher::Camellia.3pm.*
%{_mandir}/man3/Crypt::Cipher::DES.3pm.*
%{_mandir}/man3/Crypt::Cipher::DES_EDE.3pm.*
%{_mandir}/man3/Crypt::Cipher::IDEA.3pm.*
%{_mandir}/man3/Crypt::Cipher::KASUMI.3pm.*
%{_mandir}/man3/Crypt::Cipher::Khazad.3pm.*
%{_mandir}/man3/Crypt::Cipher::MULTI2.3pm.*
%{_mandir}/man3/Crypt::Cipher::Noekeon.3pm.*
%{_mandir}/man3/Crypt::Cipher::RC2.3pm.*
%{_mandir}/man3/Crypt::Cipher::RC5.3pm.*
%{_mandir}/man3/Crypt::Cipher::RC6.3pm.*
%{_mandir}/man3/Crypt::Cipher::SAFERP.3pm.*
%{_mandir}/man3/Crypt::Cipher::SAFER_K128.3pm.*
%{_mandir}/man3/Crypt::Cipher::SAFER_K64.3pm.*
%{_mandir}/man3/Crypt::Cipher::SAFER_SK128.3pm.*
%{_mandir}/man3/Crypt::Cipher::SAFER_SK64.3pm.*
%{_mandir}/man3/Crypt::Cipher::SEED.3pm.*
%{_mandir}/man3/Crypt::Cipher::Serpent.3pm.*
%{_mandir}/man3/Crypt::Cipher::Skipjack.3pm.*
%{_mandir}/man3/Crypt::Cipher::Twofish.3pm.*
%{_mandir}/man3/Crypt::Cipher::XTEA.3pm.*
%{_mandir}/man3/Crypt::Digest.3pm.*
%{_mandir}/man3/Crypt::Digest::BLAKE2b_160.3pm.*
%{_mandir}/man3/Crypt::Digest::BLAKE2b_256.3pm.*
%{_mandir}/man3/Crypt::Digest::BLAKE2b_384.3pm.*
%{_mandir}/man3/Crypt::Digest::BLAKE2b_512.3pm.*
%{_mandir}/man3/Crypt::Digest::BLAKE2s_128.3pm.*
%{_mandir}/man3/Crypt::Digest::BLAKE2s_160.3pm.*
%{_mandir}/man3/Crypt::Digest::BLAKE2s_224.3pm.*
%{_mandir}/man3/Crypt::Digest::BLAKE2s_256.3pm.*
%{_mandir}/man3/Crypt::Digest::CHAES.3pm.*
%{_mandir}/man3/Crypt::Digest::Keccak224.3pm.*
%{_mandir}/man3/Crypt::Digest::Keccak256.3pm.*
%{_mandir}/man3/Crypt::Digest::Keccak384.3pm.*
%{_mandir}/man3/Crypt::Digest::Keccak512.3pm.*
%{_mandir}/man3/Crypt::Digest::MD2.3pm.*
%{_mandir}/man3/Crypt::Digest::MD4.3pm.*
%{_mandir}/man3/Crypt::Digest::MD5.3pm.*
%{_mandir}/man3/Crypt::Digest::RIPEMD128.3pm.*
%{_mandir}/man3/Crypt::Digest::RIPEMD160.3pm.*
%{_mandir}/man3/Crypt::Digest::RIPEMD256.3pm.*
%{_mandir}/man3/Crypt::Digest::RIPEMD320.3pm.*
%{_mandir}/man3/Crypt::Digest::SHA1.3pm.*
%{_mandir}/man3/Crypt::Digest::SHA224.3pm.*
%{_mandir}/man3/Crypt::Digest::SHA256.3pm.*
%{_mandir}/man3/Crypt::Digest::SHA384.3pm.*
%{_mandir}/man3/Crypt::Digest::SHA3_224.3pm.*
%{_mandir}/man3/Crypt::Digest::SHA3_256.3pm.*
%{_mandir}/man3/Crypt::Digest::SHA3_384.3pm.*
%{_mandir}/man3/Crypt::Digest::SHA3_512.3pm.*
%{_mandir}/man3/Crypt::Digest::SHA512.3pm.*
%{_mandir}/man3/Crypt::Digest::SHA512_224.3pm.*
%{_mandir}/man3/Crypt::Digest::SHA512_256.3pm.*
%{_mandir}/man3/Crypt::Digest::SHAKE.3pm.*
%{_mandir}/man3/Crypt::Digest::Tiger192.3pm.*
%{_mandir}/man3/Crypt::Digest::Whirlpool.3pm.*
%{_mandir}/man3/Crypt::KeyDerivation.3pm.*
%{_mandir}/man3/Crypt::Mac.3pm.*
%{_mandir}/man3/Crypt::Mac::BLAKE2b.3pm.*
%{_mandir}/man3/Crypt::Mac::BLAKE2s.3pm.*
%{_mandir}/man3/Crypt::Mac::F9.3pm.*
%{_mandir}/man3/Crypt::Mac::HMAC.3pm.*
%{_mandir}/man3/Crypt::Mac::OMAC.3pm.*
%{_mandir}/man3/Crypt::Mac::PMAC.3pm.*
%{_mandir}/man3/Crypt::Mac::Pelican.3pm.*
%{_mandir}/man3/Crypt::Mac::Poly1305.3pm.*
%{_mandir}/man3/Crypt::Mac::XCBC.3pm.*
%{_mandir}/man3/Crypt::Misc.3pm.*
%{_mandir}/man3/Crypt::Mode.3pm.*
%{_mandir}/man3/Crypt::Mode::CBC.3pm.*
%{_mandir}/man3/Crypt::Mode::CFB.3pm.*
%{_mandir}/man3/Crypt::Mode::CTR.3pm.*
%{_mandir}/man3/Crypt::Mode::ECB.3pm.*
%{_mandir}/man3/Crypt::Mode::OFB.3pm.*
%{_mandir}/man3/Crypt::PK.3pm.*
%{_mandir}/man3/Crypt::PK::DH.3pm.*
%{_mandir}/man3/Crypt::PK::DSA.3pm.*
%{_mandir}/man3/Crypt::PK::ECC.3pm.*
%{_mandir}/man3/Crypt::PK::Ed25519.3pm.*
%{_mandir}/man3/Crypt::PK::RSA.3pm.*
%{_mandir}/man3/Crypt::PK::X25519.3pm.*
%{_mandir}/man3/Crypt::PRNG.3pm.*
%{_mandir}/man3/Crypt::PRNG::ChaCha20.3pm.*
%{_mandir}/man3/Crypt::PRNG::Fortuna.3pm.*
%{_mandir}/man3/Crypt::PRNG::RC4.3pm.*
%{_mandir}/man3/Crypt::PRNG::Sober128.3pm.*
%{_mandir}/man3/Crypt::PRNG::Yarrow.3pm.*
%{_mandir}/man3/Crypt::Stream::ChaCha.3pm.*
%{_mandir}/man3/Crypt::Stream::RC4.3pm.*
%{_mandir}/man3/Crypt::Stream::Rabbit.3pm.*
%{_mandir}/man3/Crypt::Stream::Salsa20.3pm.*
%{_mandir}/man3/CryptX.3pm.*
%{_mandir}/man3/Crypt::Stream::Sober128.3pm.*
%{_mandir}/man3/Crypt::Stream::Sosemanuk.3pm.*
%{_mandir}/man3/Math::BigInt::LTM.3pm.*
