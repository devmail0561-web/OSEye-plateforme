from __future__ import annotations

import logging
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

logger = logging.getLogger(__name__)

TRUSTED_KEYS_DIR = Path("/etc/oseye/plugin_keys/")


class PluginVerifier:
    """Verifies Ed25519 signatures on plugin packages.

    A plugin package is a directory or zip file containing:
      - <plugin_name>.py (or package dir)
      - <plugin_name>.sig  (detached Ed25519 signature over SHA-256 of the plugin file)

    Trusted public keys are PEM files in TRUSTED_KEYS_DIR.
    """

    def __init__(self, keys_dir: Path = TRUSTED_KEYS_DIR) -> None:
        self._keys: list[Ed25519PublicKey] = []
        self._load_keys(keys_dir)

    def _load_keys(self, keys_dir: Path) -> None:
        """Load all .pem public key files from keys_dir (silent if dir absent)."""
        if not keys_dir.is_dir():
            logger.warning("Plugin keys directory not found: %s", keys_dir)
            return

        for pem_file in sorted(keys_dir.glob("*.pem")):
            try:
                pem_data = pem_file.read_bytes()
                key = serialization.load_pem_public_key(pem_data)
                if not isinstance(key, Ed25519PublicKey):
                    logger.warning(
                        "Key %s is not an Ed25519 public key, skipping", pem_file.name
                    )
                    continue
                self._keys.append(key)
                logger.debug("Loaded trusted plugin key: %s", pem_file.name)
            except Exception:
                logger.exception("Failed to load plugin key: %s", pem_file.name)

        logger.info("Loaded %d trusted plugin key(s)", len(self._keys))

    def verify(self, plugin_path: Path, sig_path: Path) -> bool:
        """Return True if sig_path contains a valid Ed25519 signature over plugin_path contents.

        Reads plugin bytes, computes SHA-256, and verifies the signature against
        each trusted key. Returns True if any key verifies. Returns False (not raise)
        on any failure.
        """
        if not self._keys:
            logger.warning("No trusted keys loaded; verification will always fail")
            return False

        try:
            plugin_bytes = plugin_path.read_bytes()
            sig_bytes = sig_path.read_bytes()
        except OSError:
            logger.exception("Failed to read plugin or signature file")
            return False

        for key in self._keys:
            try:
                key.verify(sig_bytes, plugin_bytes)
                logger.info(
                    "Plugin signature verified for %s", plugin_path.name
                )
                return True
            except InvalidSignature:
                continue
            except Exception:
                logger.exception("Unexpected error during signature verification")
                continue

        logger.warning("Plugin signature verification failed for %s", plugin_path.name)
        return False
