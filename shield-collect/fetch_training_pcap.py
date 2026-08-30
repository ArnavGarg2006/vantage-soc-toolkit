#!/usr/bin/env python
"""
Fetch a labeled training pcap from malware-traffic-analysis.net — a site
that publishes real, labeled sample captures specifically for practicing
traffic analysis (legal, purpose-built for this). Downloading onto a real
machine deserves care even for "safe" samples: the site's own about page
warns password-protected zips whose filename contains "malware" hold live
malware samples, and any pcap here may still trip AV/Defender simply
because it's unfamiliar traffic — not because parsing it is dangerous.
This script only ever downloads and extracts (never runs, never opens)
the file, and refuses anything with "malware" in its name — in the URL or
inside the zip itself — as an extra guard against accidentally pulling a
live sample instead of a traffic-analysis pcap.

Password scheme (from the site's own about page, confirmed live): the
password for a given day's zip archives is the word "infected" followed
by an underscore followed by the date as YYYYMMDD. Derived from a --date
argument here rather than hardcoded to any one password.

Usage:
    python fetch_training_pcap.py <zip-url> --date 2026-08-09
"""
import argparse
import sys
import zipfile
from pathlib import Path
from urllib.request import urlretrieve

sys.stdout.reconfigure(encoding="utf-8")

DEST_DIR = Path(__file__).resolve().parent / "training-pcaps"


def fetch(url, date):
    # Check the FILENAME only, not the whole URL - the site's own domain is
    # literally "malware-traffic-analysis.net", so checking the full URL
    # string flags every single link on the site, including the safe ones.
    zip_name = url.rsplit("/", 1)[-1]
    if "malware" in zip_name.lower():
        print(f"Refusing: filename '{zip_name}' contains 'malware' — per the site's own "
              f"convention that names a live malware sample, not a traffic-analysis pcap. "
              f"This tool only ever fetches labeled TRAFFIC captures.")
        sys.exit(1)

    DEST_DIR.mkdir(exist_ok=True)
    zip_path = DEST_DIR / zip_name
    print(f"Downloading {url}\n  -> {zip_path} ...")
    urlretrieve(url, zip_path)
    print(f"Downloaded {zip_path.stat().st_size / 1e6:.1f} MB.")

    pw_str = f"infected_{date.replace('-', '')}"
    with zipfile.ZipFile(zip_path) as z:
        names = z.namelist()
        if any("malware" in n.lower() for n in names):
            print("Refusing to extract: an entry inside the zip has 'malware' in its "
                  "name — a live sample, not a plain pcap. Leaving the zip in place, "
                  "not extracting it.")
            sys.exit(1)
        print(f"Extracting with password scheme '{pw_str}' ...")
        z.extractall(path=DEST_DIR, pwd=pw_str.encode())
        print(f"Extracted: {', '.join(names)}")

    print(f"\nDone. Files are in {DEST_DIR} — analyze with "
          f"shield-collect/scapy_pcap_analysis.py or shield-collect/pcap_analysis.py.")


def main():
    parser = argparse.ArgumentParser(
        description="Fetch a labeled training pcap from malware-traffic-analysis.net.")
    parser.add_argument("url", help="Direct .pcap.zip URL from a training-exercises blog post")
    parser.add_argument("--date", required=True,
                         help="Blog post date, YYYY-MM-DD (used to derive the zip password)")
    args = parser.parse_args()
    fetch(args.url, args.date)


if __name__ == "__main__":
    main()
