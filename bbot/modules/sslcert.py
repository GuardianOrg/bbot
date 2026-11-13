import asyncio
import datetime
import ipaddress
import ssl
from OpenSSL import crypto
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed25519, ed448, rsa
from urllib3.util.ssl_match_hostname import CertificateError, match_hostname
from contextlib import suppress
from urllib.parse import urlparse

from bbot.errors import ValidationError
from bbot.modules.base import BaseModule
from bbot.core.helpers.async_helpers import NamedLock
from bbot.core.helpers.certificate_findings import initial_certificate_findings
from bbot.core.helpers.web.ssl_context import ssl_context_noverify


class sslcert(BaseModule):
    watched_events = ["OPEN_TCP_PORT", "URL", "HTTP_RESPONSE"]
    produced_events = ["DNS_NAME", "EMAIL_ADDRESS", "TLS_CERTIFICATE", "FINDING"]
    flags = ["affiliates", "subdomain-enum", "email-enum", "active", "safe", "web-basic", "service-web"]
    meta = {
        "description": "Visit open ports and retrieve SSL certificates",
        "created_date": "2022-03-30",
        "author": "@TheTechromancer",
    }
    options = {"timeout": 5.0, "skip_non_ssl": True}
    options_desc = {"timeout": "Socket connect timeout in seconds", "skip_non_ssl": "Don't try common non-SSL ports"}
    deps_apt = ["openssl"]
    deps_pip = ["pyOpenSSL~=25.3.0", "urllib3>=2,<3"]
    _module_threads = 25
    scope_distance_modifier = 1
    _priority = 2

    async def setup(self):
        self.timeout = self.config.get("timeout", 5.0)
        self.skip_non_ssl = self.config.get("skip_non_ssl", True)
        self.non_ssl_ports = (22, 53, 80)

        # sometimes we run into a server with A LOT of SANs
        # these are usually stupid and useless, so we abort based on a different threshold
        # depending on whether the parent event is in scope
        self.in_scope_abort_threshold = 50
        self.out_of_scope_abort_threshold = 10

        self.hosts_visited = set()
        self.ip_lock = NamedLock()
        return True

    async def filter_event(self, event):
        if event.type in ("URL", "HTTP_RESPONSE"):
            url = event.data.get("url", "") if isinstance(event.data, dict) else str(event.data)
            parsed = urlparse(url)
            if parsed.scheme.lower() != "https":
                return False, "only accepts HTTPS URLs"
            return True
        if self.skip_non_ssl and event.port in self.non_ssl_ports:
            return False, f"Port {event.port} doesn't typically use SSL"
        return True

    async def handle_event(self, event):
        url = None
        if event.type in ("URL", "HTTP_RESPONSE"):
            url = event.data.get("url", "") if isinstance(event.data, dict) else str(event.data)
            parsed = urlparse(url)
            _host = parsed.hostname or event.host
            port = parsed.port or 443
        else:
            _host = event.host
            if event.port:
                port = event.port
            else:
                port = 443
            if _host:
                url = f"https://{self.helpers.make_netloc(_host, port)}/"

        # turn hostnames into IP address(es)
        if self.helpers.is_ip(_host):
            hosts = [_host]
        else:
            hosts = list(await self.helpers.resolve(_host))

        if event.scope_distance == 0:
            abort_threshold = self.in_scope_abort_threshold
        else:
            abort_threshold = self.out_of_scope_abort_threshold

        server_name = None if self.helpers.is_ip(_host) else str(_host)
        tasks = [self.visit_host(host, port, server_name=server_name) for host in hosts]
        async for task in self.helpers.as_completed(tasks):
            result = await task
            if not isinstance(result, tuple) or not len(result) == 4:
                continue
            dns_names, emails, cert_data, (host, port) = result
            if cert_data:
                cert_event_data = {
                    **cert_data,
                    "host": str(event.host or _host or host),
                    "url": url,
                    "port": port,
                }
                await self.emit_event(
                    cert_event_data,
                    "TLS_CERTIFICATE",
                    parent=event,
                    context=f"{{module}} retrieved TLS certificate metadata from {cert_event_data['host']}:{port}",
                )
                await self.emit_initial_findings(cert_event_data, event)
                if server_name is None:
                    await self.recheck_scoped_san_hosts(event, cert_data, str(host), port)
            if len(dns_names) > abort_threshold:
                netloc = self.helpers.make_netloc(host, port)
                self.verbose(
                    f"Skipping Subject Alternate Names (SANs) on {netloc} because number of hostnames ({len(dns_names):,}) exceeds threshold ({abort_threshold})"
                )
                dns_names = dns_names[:1] + [n for n in dns_names[1:] if self.scan.in_scope(n)]
            for event_type, results in (("DNS_NAME", set(dns_names)), ("EMAIL_ADDRESS", emails)):
                for event_data in results:
                    if event_data is not None and event_data != event.data:
                        self.debug(f"Discovered new {event_type} via SSL certificate parsing: [{event_data}]")
                        try:
                            ssl_event = self.make_event(event_data, event_type, parent=event, raise_error=True)
                            parent_event = ssl_event.get_parent()
                            if parent_event.scope_distance == 0:
                                tags = ["affiliate"]
                            else:
                                tags = None
                            if ssl_event:
                                await self.emit_event(
                                    ssl_event,
                                    tags=tags,
                                    context=f"{{module}} parsed SSL certificate at {event.data} and found {{event.type}}: {{event.data}}",
                                )
                        except ValidationError as e:
                            self.hugeinfo(f'Malformed {event_type} "{event_data}" at {event.data}')
                            self.debug(f"Invalid data at {host}:{port}: {e}")

    def on_success_callback(self, event):
        parent_scope_distance = event.get_parent().scope_distance
        if parent_scope_distance == 0 and event.scope_distance > 0:
            event.add_tag("affiliate")

    async def recheck_scoped_san_hosts(self, event, cert_data, address, port):
        """Recheck a discovered IP with SNI for in-scope names that still resolve to it."""
        names = sorted(
            {
                normalized
                for raw_name in cert_data.get("certSanDomains", [])
                if isinstance(raw_name, str)
                if (normalized := raw_name.lower().rstrip("."))
                and "*" not in normalized
                and self.scan.in_scope(normalized)
            }
        )
        semaphore = asyncio.Semaphore(8)

        async def recheck(name):
            async with semaphore:
                addresses = await self.helpers.resolve(name)
                if address not in {str(candidate) for candidate in addresses}:
                    return
                result = await self.visit_host(address, port, server_name=name)
                if not isinstance(result, tuple) or len(result) != 4 or not result[2]:
                    return
                metadata = result[2]
                payload = {
                    **metadata,
                    "host": name,
                    "url": f"https://{self.helpers.make_netloc(name, port if port != 443 else None)}/",
                    "port": port,
                }
                await self.emit_event(
                    payload,
                    "TLS_CERTIFICATE",
                    parent=event,
                    context=f"{{module}} rechecked TLS certificate for {name}:{port} with SNI",
                )

                await self.emit_initial_findings(payload, event)

        await asyncio.gather(*(recheck(name) for name in names))

    async def emit_initial_findings(self, data, parent):
        host = str(data.get("host") or "")
        if not self.scan.in_scope(host):
            return
        explicit_ip = False
        if self.helpers.is_ip(host):
            # A CIDR or a discovered edge address does not make its default leaf a target.
            seeds = getattr(getattr(getattr(self.scan, "target", None), "seeds", None), "event_seeds", {})
            for seed in seeds:
                if seed.type == "IP_ADDRESS" and str(seed.data) == host:
                    explicit_ip = True
                elif seed.type in ("URL", "URL_UNVERIFIED"):
                    url = urlparse(str(seed.data))
                    explicit_ip |= url.scheme == "https" and url.hostname == host and (url.port or 443) == data.get("port", 443)
        for finding in initial_certificate_findings(data, explicit_ip=explicit_ip):
            await self.emit_event(finding, "FINDING", parent=parent,
                                  context="{module} recorded a verified initial TLS certificate issue")

    async def visit_host(self, host, port, server_name=None):
        host = self.helpers.make_ip_type(host)
        netloc = self.helpers.make_netloc(host, port)
        host_hash = hash((host, port, server_name))
        dns_names = []
        emails = set()
        async with self.ip_lock.lock(host_hash):
            if host_hash in self.hosts_visited:
                self.debug(f"Already processed {host} on port {port}, skipping")
                return [], [], None, (host, port)
            else:
                self.hosts_visited.add(host_hash)

            host = str(host)

            # Connect to the host
            try:
                transport, _ = await asyncio.wait_for(
                    self.helpers.loop.create_connection(
                        lambda: asyncio.Protocol(), host, port, ssl=ssl_context_noverify, server_hostname=server_name
                    ),
                    timeout=self.timeout,
                )
            except asyncio.TimeoutError:
                self.debug(f"Timed out after {self.timeout} seconds while connecting to {netloc}")
                return [], [], None, (host, port)
            except Exception as e:
                log_fn = self.warning
                if isinstance(e, OSError):
                    log_fn = self.debug
                log_fn(f"Error connecting to {netloc}: {e}")
                return [], [], None, (host, port)
            finally:
                with suppress(Exception):
                    transport.close()

            # Get the SSL object
            try:
                ssl_object = transport.get_extra_info("ssl_object")
            except Exception as e:
                self.verbose(f"Error getting ssl_object: {e}", trace=True)
                return [], [], None, (host, port)

            # Get the certificate
            try:
                der = ssl_object.getpeercert(binary_form=True)
            except Exception as e:
                self.verbose(f"Error getting peer cert: {e}", trace=True)
                return [], [], None, (host, port)
            try:
                cert = crypto.load_certificate(crypto.FILETYPE_ASN1, der)
            except Exception as e:
                self.verbose(f"Error loading certificate: {e}", trace=True)
                return [], [], None, (host, port)
            issuer = cert.get_issuer()
            if issuer.emailAddress and self.helpers.regexes.email_regex.match(issuer.emailAddress):
                emails.add(issuer.emailAddress)
            subject = cert.get_subject()
            if subject.emailAddress and self.helpers.regexes.email_regex.match(subject.emailAddress):
                emails.add(subject.emailAddress)
            common_name = str(subject.commonName).lstrip("*.").lower()
            dns_names = set(self.get_cert_sans(cert))
            with suppress(KeyError):
                dns_names.remove(common_name)
            dns_names = [common_name] + list(dns_names)
            peer_chain = self.get_peer_chain(ssl_object)
            cert_data = self.get_cert_metadata(cert, host=server_name or host, peer_chain=peer_chain)
        return dns_names, list(emails), cert_data, (host, port)

    @classmethod
    def get_cert_metadata(cls, cert, *, host=None, peer_chain=None, trust_store=None):
        subject = cert.get_subject()
        issuer = cert.get_issuer()
        not_after = cls.parse_asn1_time(cert.get_notAfter())
        fingerprint = cert.digest("sha256").decode().replace(":", "").lower()
        subject_components = cls.name_components(subject)
        issuer_components = cls.name_components(issuer)
        # The names the certificate actually covers, wildcards included, so consumers can check
        # hostname coverage. Discovery uses get_cert_sans, which reduces wildcards to their parent.
        san_domains = sorted({name for name in cls.get_cert_san_entries(cert) if name})
        public_key = cert.to_cryptography().public_key()
        key_type, key_bits = cls.public_key_metadata(public_key)
        validation = cls.validate_certificate(cert, host, san_domains, peer_chain, trust_store)
        return {
            **validation,
            "certIssuerOrganization": issuer_components.get("O"),
            "certKeyType": key_type,
            "certKeyBits": key_bits,
            "certificate": {
                "pem": crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode("ascii"),
                "subject": subject_components,
                "issuer": issuer_components,
                "serialNumber": str(cert.get_serial_number()),
                "version": cert.get_version(),
                "notBefore": cls.parse_asn1_time(cert.get_notBefore()),
                "notAfter": not_after,
                "fingerprintSha256": fingerprint,
                "sanDomains": san_domains,
                "keyType": key_type,
                "keyBits": key_bits,
                "chainTrusted": validation["certChainTrusted"],
                "hostnameValid": validation["certHostnameValid"],
                "validationError": validation["certValidationError"],
                "chainPem": [crypto.dump_certificate(crypto.FILETYPE_PEM, item).decode("ascii") for item in peer_chain]
                if peer_chain is not None
                else None,
            },
            "certSubjectCn": subject_components.get("CN"),
            "certIssuerCn": issuer_components.get("CN"),
            "certFingerprintSha256": fingerprint,
            "certSanDomains": san_domains,
            "certNotAfter": not_after,
            "certIsExpired": cert.has_expired(),
        }

    @staticmethod
    def public_key_metadata(key):
        for algorithm, kind, fallback_bits in (
            (rsa.RSAPublicKey, "rsa", None),
            (ec.EllipticCurvePublicKey, "ec", None),
            (dsa.DSAPublicKey, "dsa", None),
            (ed25519.Ed25519PublicKey, "ed25519", 256),
            (ed448.Ed448PublicKey, "ed448", 448),
        ):
            if isinstance(key, algorithm):
                return kind, getattr(key, "key_size", fallback_bits)
        raise ValueError(f"Unsupported TLS public key type: {type(key).__name__}")

    @staticmethod
    def get_peer_chain(ssl_object):
        # CPython exposed this publicly in 3.13; its underlying TLS object also
        # provides the chain on the production 3.11 runtime. Missing is unknown.
        getter = getattr(ssl_object, "get_unverified_chain", None)
        if getter is None:
            getter = getattr(getattr(ssl_object, "_sslobj", None), "get_unverified_chain", None)
        if getter is None:
            return None
        result = []
        for item in getter() or []:
            if isinstance(item, crypto.X509):
                result.append(item)
                continue
            raw = item if isinstance(item, (str, bytes)) else item.public_bytes()
            if isinstance(raw, str):
                raw = raw.encode()
            encoding = crypto.FILETYPE_PEM if raw.startswith(b"-----BEGIN") else crypto.FILETYPE_ASN1
            result.append(crypto.load_certificate(encoding, raw))
        return result

    @staticmethod
    def validate_certificate(cert, host, sans, peer_chain, trust_store):
        chain_trusted, hostname_valid, validation_error = None, None, None
        if peer_chain is not None:
            if trust_store is None:
                trust_store = crypto.X509Store()
                roots = ssl.get_default_verify_paths()
                if not roots.cafile and not roots.capath:
                    raise RuntimeError("No CA trust store available for initial TLS verification")
                trust_store.load_locations(roots.cafile, roots.capath)
            try:
                crypto.X509StoreContext(trust_store, cert, peer_chain[1:]).verify_certificate()
                chain_trusted = True
            except crypto.X509StoreContextError:
                chain_trusted = False
                validation_error = "expired" if cert.has_expired() else "untrusted-chain"
        if host:
            names = []
            for name in sans:
                try:
                    ipaddress.ip_address(name)
                    names.append(("IP Address", name))
                except ValueError:
                    names.append(("DNS", name))
            peer = {"subjectAltName": names, "subject": ((("commonName", str(cert.get_subject().CN or "")),),)}
            try:
                match_hostname(peer, str(host), hostname_checks_common_name=True)
                hostname_valid = True
            except CertificateError:
                hostname_valid = False
                validation_error = validation_error or "hostname-mismatch"
        authorized = (
            (chain_trusted and hostname_valid) if chain_trusted is not None and hostname_valid is not None else None
        )
        return {
            "certChainTrusted": chain_trusted,
            "certHostnameValid": hostname_valid,
            "certAuthorized": authorized,
            "certValidationError": validation_error,
        }

    @staticmethod
    def name_components(name):
        components = {}
        for key, value in name.get_components():
            key = key.decode(errors="ignore")
            value = value.decode(errors="ignore")
            if key and value:
                components[key] = value
        return components

    @staticmethod
    def parse_asn1_time(value):
        if isinstance(value, bytes):
            value = value.decode(errors="ignore")
        if not value:
            return None
        try:
            parsed = datetime.datetime.strptime(str(value), "%Y%m%d%H%M%SZ")
        except ValueError:
            return None
        return parsed.replace(tzinfo=datetime.timezone.utc).isoformat()

    @staticmethod
    def get_cert_san_entries(cert):
        try:
            extension = cert.to_cryptography().extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        except x509.ExtensionNotFound:
            return []
        # URI/email SANs are identities of other kinds, not DNS names to discover
        # or compare against the endpoint's hostname.
        return [str(name).lower() for name in extension.get_values_for_type(x509.DNSName)] + [
            str(address) for address in extension.get_values_for_type(x509.IPAddress)
        ]

    @classmethod
    def get_cert_sans(cls, cert):
        return [name.lstrip("*.") for name in cls.get_cert_san_entries(cert)]
