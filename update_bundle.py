import datetime
import hashlib
import io
import pathlib
import shutil
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

# We update the version in this file
VERSION_FILE = PACKAGE_DIR / "__init__.py"


# First fetch all data
def fetch_to_file(url: str, path: pathlib.Path) -> None:
    """Fetches the provided URL and writes it to the provided path."""
    with requests.get(url, stream=True) as r, open(str(path), "wb") as f:
        r.raise_for_status()
        for chunk in r.iter_content(chunk_size=8192):
            f.write(chunk)


def hash_file(path: pathlib.Path) -> str:
    """Returns a simple (md5) hash of the provided path. Used to check whether
    the file contents have changed.
    """
    hash = hashlib.md5()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(hash.block_size)
            if not chunk:
                break
            hash.update(chunk)
    return hash.hexdigest()


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
        print(subject.friendly_name[:-1], f"{i + 1} / {len(ctl.subjects)}")

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
        name = subject.friendly_name[:-1].encode('ascii', 'ignore').decode()
        if name != subject.friendly_name[:-1]:
            f.write(f"# Friendly Name (ASCII): {name}\n")
        else:
            f.write(f"# Friendly Name: {name}\n")

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


def patch_version(filename: pathlib.Path = VERSION_FILE) -> None:
    """Changes the date-based version number in the provided file."""
    cache = io.StringIO()
    with open(filename, "r") as f:
        for line in f:
            if line.startswith("__version__"):
                today = datetime.date.today()
                # write it quite ugly, but this ensures that we do not have
                # leading zeroes
                cache.write(
                    f'__version__ = "{today.year}.{today.month}.{today.day}"\n'
                )
            else:
                cache.write(line)
    cache.seek(0)
    with open(filename, "w") as f:
        shutil.copyfileobj(cache, f)


def main() -> None:
    # Calculate current hash to see if contents have changed
    if AUTHROOTSTL_PATH.exists():
        old_hash = hash_file(AUTHROOTSTL_PATH)
    else:
        old_hash = ""

    # Download new file and hash
    fetch_to_file(AUTHROOTSTL_URL, AUTHROOTSTL_PATH)
    new_hash = hash_file(AUTHROOTSTL_PATH)

    # let signify parse the CertificateTrustList for us
    ctl = CertificateTrustList.from_stl_file(AUTHROOTSTL_PATH)
    print(f"Fetched CTL file, there are {len(ctl.subjects)} subjects")

    # fetch all certificates to cache
    fetch_certificates(ctl)
    print("Fetched all certificates to cache")

    # dump certificates to bundle
    with open(BUNDLE_PATH, "w", encoding='utf-8') as f:
        for subject in ctl.subjects:
            dump_certificate(f, subject)
    print(f"Dumped certificates to {BUNDLE_PATH}")

    # patch version if needed
    if old_hash != new_hash:
        patch_version()
        print(f"Patched version number in {VERSION_FILE}")
    else:
        print("Did not patch version number because contents have not changed.")


if __name__ == '__main__':
    main()
