from __future__ import annotations

import ipaddress
import re
import unicodedata
from typing import Any
from urllib.parse import urlsplit

import tldextract
from rapidfuzz import fuzz


KNOWN_BRAND_DOMAINS = [
    "google.com",
    "gmail.com",
    "accounts.google.com",
    "microsoft.com",
    "office.com",
    "office365.com",
    "outlook.com",
    "live.com",
    "login.microsoftonline.com",
    "apple.com",
    "icloud.com",
    "amazon.com",
    "aws.amazon.com",
    "github.com",
    "gitlab.com",
    "dropbox.com",
    "slack.com",
    "zoom.us",
    "notion.so",
    "atlassian.com",
    "jira.com",
    "confluence.atlassian.com",
    "adobe.com",
    "docusign.com",
    "salesforce.com",
    "paypal.com",
    "stripe.com",
    "wise.com",
    "revolut.com",
    "westernunion.com",
    "booking.com",
    "airbnb.com",
    "allegro.pl",
    "olx.pl",
    "otomoto.pl",
    "aliorbank.pl",
    "ing.pl",
    "ingbank.pl",
    "santander.pl",
    "santanderconsumer.pl",
    "pkobp.pl",
    "ipko.pl",
    "inteligo.pl",
    "mbank.pl",
    "millennium.pl",
    "bankmillennium.pl",
    "pekao.com.pl",
    "bnpparibas.pl",
    "credit-agricole.pl",
    "velobank.pl",
    "bosbank.pl",
    "nestbank.pl",
    "bankpocztowy.pl",
    "citi.com",
    "citibank.pl",
    "gov.pl",
    "obywatel.gov.pl",
    "login.gov.pl",
    "epuap.gov.pl",
    "podatki.gov.pl",
    "zus.pl",
    "nfz.gov.pl",
    "pacjent.gov.pl",
    "moj.gov.pl",
    "cepik.gov.pl",
    "biznes.gov.pl",
    "praca.gov.pl",
    "amu.edu.pl",
    "rekrutacja.amu.edu.pl",
    "usosweb.amu.edu.pl",
    "poczta.amu.edu.pl",
    "st.amu.edu.pl",
    "wa.amu.edu.pl",
    "uam.pl",
    "uw.edu.pl",
    "uj.edu.pl",
    "agh.edu.pl",
    "pw.edu.pl",
    "put.poznan.pl",
    "ue.poznan.pl",
    "uew.pl",
    "sggw.edu.pl",
    "pg.edu.pl",
    "pwr.edu.pl",
    "kul.pl",
    "umk.pl",
    "proton.me",
    "protonmail.com",
    "yahoo.com",
    "yandex.com",
    "mail.com",
    "zoho.com",
    "fastmail.com",
    "inpost.pl",
    "dhl.com",
    "dhlparcel.pl",
    "dpd.com",
    "dpd.com.pl",
    "ups.com",
    "fedex.com",
    "poczta-polska.pl",
    "orlenpaczka.pl",
    "gls-poland.com",
    "meestpost.com",
    "orange.pl",
    "play.pl",
    "plus.pl",
    "t-mobile.pl",
    "vectra.pl",
    "inea.pl",
    "netia.pl",
    "upc.pl",
    "enea.pl",
    "eon.pl",
    "tauron.pl",
    "pgnig.pl",
    "veolia.pl",
    "pepco.pl",
    "ikea.com",
    "otodom.pl",
    "morizon.pl",
    "gratka.pl",
    "netflix.com",
    "spotify.com",
    "disneyplus.com",
    "hbomax.com",
    "primevideo.com",
    "youtube.com",
    "facebook.com",
    "instagram.com",
    "linkedin.com",
    "x.com",
    "twitter.com",
    "tiktok.com",
    "reddit.com",
    "discord.com",
    "akamai.com",
    "cloudflare.com",
    "okta.com",
    "duo.com",
    "auth0.com",
    "onepassword.com",
    "lastpass.com",
    "bitwarden.com",
    "virustotal.com",
    "shodan.io",
    "haveibeenpwned.com",
    "docker.com",
    "kubernetes.io",
    "python.org",
    "pypi.org",
    "npmjs.com",
]

SHORTENER_DOMAINS = {
    "bit.ly",
    "t.co",
    "tinyurl.com",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "buff.ly",
    "cutt.ly",
    "rebrand.ly",
    "shorturl.at",
    "s.id",
    "tiny.cc",
    "lnkd.in",
    "rb.gy",
}

SUSPICIOUS_KEYWORDS = {
    "login",
    "secure",
    "security",
    "verify",
    "verification",
    "update",
    "support",
    "account",
    "billing",
    "auth",
    "password",
    "reset",
}

TLD_EXTRACTOR = tldextract.TLDExtract(suffix_list_urls=(), fallback_to_snapshot=True)

URL_PATTERN = re.compile(r"(?i)\b((?:https?://|www\.)[^\s<>'\"\]]+)")


def _normalize_text(value: str) -> str:
    decomposed = unicodedata.normalize("NFKD", value or "")
    stripped = "".join(char for char in decomposed if not unicodedata.combining(char))
    return stripped.lower()


def _normalize_domain(domain: str) -> str:
    domain = (domain or "").strip().lower().rstrip(".")
    domain = domain.split(":", 1)[0]
    return _normalize_text(domain)


def _root_domain(domain: str) -> str:
    extracted = TLD_EXTRACTOR(domain or "")
    if extracted.domain and extracted.suffix:
        return f"{extracted.domain}.{extracted.suffix}".lower()
    return (domain or "").lower().strip(".")


def _safe_urlsplit(url: str):
    candidate = url if re.match(r"(?i)^https?://", url) else f"https://{url}"
    return urlsplit(candidate)


def extract_urls_from_text(text: str) -> list[str]:
    matches = URL_PATTERN.findall(text or "")
    urls: list[str] = []
    seen: set[str] = set()
    for match in matches:
        cleaned = match.rstrip(".,;:!?)]}\"")
        if cleaned not in seen:
            seen.add(cleaned)
            urls.append(cleaned)
    return urls


def _trusted_domain_sets() -> tuple[set[str], set[str], set[str]]:
    trusted_exact = {_normalize_domain(domain) for domain in KNOWN_BRAND_DOMAINS}
    trusted_roots = {_root_domain(domain) for domain in KNOWN_BRAND_DOMAINS}
    brand_tokens: set[str] = set()
    for domain in KNOWN_BRAND_DOMAINS:
        parts = [part for part in _normalize_domain(domain).split(".") if part]
        for part in parts:
            if part not in {"com", "pl", "edu", "gov", "us", "so", "io", "me", "net", "org", "co"} and len(part) > 2:
                brand_tokens.add(part)
    return trusted_exact, trusted_roots, brand_tokens


TRUSTED_EXACT_DOMAINS, TRUSTED_ROOT_DOMAINS, BRAND_TOKENS = _trusted_domain_sets()


def _register_evidence(url: str, issue: str, explanation: str, points: int, evidence: list[dict[str, Any]], total_points: list[int]) -> None:
    evidence.append(
        {
            "url": url,
            "issue": issue,
            "explanation": explanation,
            "points": points,
        }
    )
    total_points[0] += points


def analyze_urls(body_text: str) -> dict[str, Any]:
    extracted_urls = extract_urls_from_text(body_text)
    evidence: list[dict[str, Any]] = []
    total_points = [0]

    if len(extracted_urls) > 3:
        _register_evidence(
            extracted_urls[0],
            "Many URLs",
            f"The message contains {len(extracted_urls)} URLs, which increases review complexity.",
            5,
            evidence,
            total_points,
        )

    for url in extracted_urls:
        split_result = _safe_urlsplit(url)
        hostname = (split_result.hostname or "").strip().lower()
        normalized_hostname = _normalize_domain(hostname)
        root_domain = _root_domain(hostname)
        root_normalized = _normalize_domain(root_domain)
        root_labels = [label for label in root_normalized.split(".") if label]
        trusted_exact = normalized_hostname in TRUSTED_EXACT_DOMAINS
        trusted_root = root_domain in TRUSTED_ROOT_DOMAINS
        is_trusted = trusted_exact or trusted_root

        if split_result.scheme.lower() == "http":
            _register_evidence(
                url,
                "HTTP instead of HTTPS",
                "The link uses plain HTTP rather than HTTPS.",
                5,
                evidence,
                total_points,
            )

        try:
            ipaddress.ip_address(hostname)
            _register_evidence(
                url,
                "IP-based URL",
                "The link uses a raw IP address instead of a domain name.",
                10,
                evidence,
                total_points,
            )
        except ValueError:
            pass

        if hostname.startswith("xn--") or any(label.startswith("xn--") for label in hostname.split(".")):
            _register_evidence(
                url,
                "Punycode domain",
                "The hostname uses punycode, which can hide lookalike characters.",
                15,
                evidence,
                total_points,
            )

        if hostname in SHORTENER_DOMAINS or root_domain in SHORTENER_DOMAINS:
            _register_evidence(
                url,
                "Shortened URL",
                "The link uses a known URL shortener.",
                12,
                evidence,
                total_points,
            )

        if not is_trusted and len(hostname) > 30:
            _register_evidence(
                url,
                "Long hostname",
                "The domain is unusually long, which can be used to hide deceptive wording.",
                5,
                evidence,
                total_points,
            )

        if not is_trusted and hostname.count(".") >= 3:
            _register_evidence(
                url,
                "Many subdomains",
                "The hostname uses multiple subdomains, which can make the true destination harder to inspect.",
                5,
                evidence,
                total_points,
            )

        if not is_trusted:
            brand_matches = [brand for brand in BRAND_TOKENS if brand and brand in normalized_hostname]
            if brand_matches:
                keyword_matches = [keyword for keyword in SUSPICIOUS_KEYWORDS if keyword in normalized_hostname]
                if keyword_matches:
                    _register_evidence(
                        url,
                        "Official-looking fake domain",
                        f"The domain combines a brand-like token with suspicious terms such as {', '.join(sorted(set(keyword_matches)))}.",
                        15,
                        evidence,
                        total_points,
                    )
                else:
                    _register_evidence(
                        url,
                        "Brand name inside non-official domain",
                        f"The domain contains a brand-like token ({', '.join(sorted(set(brand_matches)))}), but the root domain is not trusted.",
                        10,
                        evidence,
                        total_points,
                    )

            best_similarity = 0
            closest_brand = ""
            for trusted in TRUSTED_ROOT_DOMAINS:
                similarity = fuzz.ratio(root_normalized, _normalize_domain(trusted))
                if similarity > best_similarity:
                    best_similarity = similarity
                    closest_brand = trusted
            if best_similarity >= 85 and root_domain != closest_brand:
                _register_evidence(
                    url,
                    "Lookalike domain",
                    f"The domain is visually similar to {closest_brand} (similarity {best_similarity}%).",
                    20,
                    evidence,
                    total_points,
                )

    url_risk_score = max(0, min(100, total_points[0]))

    return {
        "url_risk_score": url_risk_score,
        "extracted_urls": extracted_urls,
        "evidence": evidence,
    }
