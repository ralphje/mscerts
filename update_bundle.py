import pathlib
import typing
from typing import cast

import requests
import asn1crypto.pem
from asn1crypto.x509 import KeyPurposeId
from signify.authenticode.authroot import CertificateTrustList, \
    CertificateTrustSubject

PACKAGE_DIR = pathlib.Path(__file__).resolve().parent / "mscerts"

# This is where we fetch and store the STL-file
AUTHROOTSTL_URL = "http://ctldl.windowsupdate.com/msdownload/update/v3/static/trustedr/en/authroot.stl"
AUTHROOTSTL_PATH = PACKAGE_DIR / "authroot.stl"

# This is where we fetch the individual certificates from
CERT_URL = "http://ctldl.windowsupdate.com/msdownload/update/v3/static/trustedr/en/{}.crt"

# Certificates are cached here
CACHE_PATH = pathlib.Path(__file__).resolve().parent / ".cache" / "certs"
CACHE_PATH.mkdir(parents=True, exist_ok=True)

# And we generate one big bundle here
BUNDLE_PATH = PACKAGE_DIR / "cacert.pem"


# First fetch all data
def fetch_to_file(url: str, path: pathlib.Path) -> None:
    """Fetches the provided URL and writes it to the provided path."""
    with requests.get(url, stream=True) as r, open(str(path), "wb") as f:
        r.raise_for_status()
        for chunk in r.iter_content(chunk_size=8192):
            f.write(chunk)


def check_certificate_in_cache(
    identifier: str,
    cache_path: pathlib.Path = CACHE_PATH,
) -> bool:
    """Checks whether the identifier is already present in the cache."""
    if not (cache_path / identifier).exists():
        return False
    with open(cache_path / identifier, "r") as cert_file:
        content = cert_file.read()
        if "-----END CERTIFICATE-----" not in content:
            print(f"Invalid cached certificate, adding {identifier} again")
            return False
    return True


def fetch_certificate(identifier: str, cert_url: str = CERT_URL) -> None:
    """Fetches the certificate by identifier from the certificate URL,
    and writes it armored to the cache directory.
    """

    r = requests.get(cert_url.format(identifier))
    r.raise_for_status()
    with open(CACHE_PATH / identifier, "wb") as f:
        f.write(asn1crypto.pem.armor("CERTIFICATE", r.content))
    print(f"- Fetched certificate {identifier}")


def fetch_certificates(ctl: CertificateTrustList) -> None:
    """Fetches all certificates in the CertificateTrustList"""

    for i, subject in enumerate(ctl.subjects):
        print(subject.friendly_name, f"{i + 1} / {len(ctl.subjects)}")

        if check_certificate_in_cache(subject.identifier.hex()):
            continue
        fetch_certificate(subject.identifier.hex())


def readable_eku(eku: tuple[int, ...]) -> str:
    """Utility function to ensure that the EKU is made as readible as possible.
    """

    dotted = ".".join(map(str, eku))
    return cast(dict[str, str], KeyPurposeId._map).get(dotted, dotted)


def readable_ekus(ekus: list[tuple[int, ...]]) -> list[str]:
    """Utility function to convert all EKUs in a list with readable_eku."""
    return [readable_eku(x) for x in ekus]


def dump_certificate(
    f: typing.TextIO,
    subject: CertificateTrustSubject,
) -> None:
    """Dump an individual certificate to an already-open file."""

    with open(CACHE_PATH / subject.identifier.hex(), "r") as cert_file:
        certificate_body = cert_file.read()

    f.write(f"# Subject Identifier: {subject.identifier.hex()}\n")
    if subject.friendly_name:
        f.write(f"# Friendly Name: {subject.friendly_name[:-1]}\n")
    if subject.extended_key_usages:
        f.write(
            f"# Extended key usages: "
            f"{readable_ekus(subject.extended_key_usages)}\n"
        )
    if subject.subject_name_md5:
        f.write(f"# Subject Name MD5: {subject.subject_name_md5.hex()}\n")
    if subject.disallowed_filetime:
        f.write(f"# Disallowed Filetime: {subject.disallowed_filetime}\n")
    if subject.root_program_chain_policies:
        f.write(
            "# Root Program Chain Policies: "
            f"{readable_ekus(subject.root_program_chain_policies)}\n"
        )
    if subject.disallowed_extended_key_usages:
        f.write(
            "# Disallowed extended key usages: "
            f"{readable_ekus(subject.disallowed_extended_key_usages)}\n"
        )
    if subject.not_before_filetime:
        f.write(f"# Not before Filetime: {subject.not_before_filetime}\n")
    if subject.not_before_extended_key_usages:
        f.write(
            "# Not before extended key usages: "
            f"{readable_ekus(subject.not_before_extended_key_usages)}\n"
        )

    f.write(certificate_body)
    f.write("\n")


def main() -> None:
    fetch_to_file(AUTHROOTSTL_URL, AUTHROOTSTL_PATH)
    # let signify parse the CertificateTrustList for us
    ctl = CertificateTrustList.from_stl_file(AUTHROOTSTL_PATH)
    print(f"Fetched CTL file, there are {len(ctl.subjects)} subjects")

    fetch_certificates(ctl)
    print("Fetched all certificates to cache")

    with open(BUNDLE_PATH, "w", encoding='utf-8') as f:
        for subject in ctl.subjects:
            dump_certificate(f, subject)
    print(f"Dumped certificates to {BUNDLE_PATH}")


if __name__ == '__main__':
    main()
