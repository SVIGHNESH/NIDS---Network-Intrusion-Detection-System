"""
nids/core/config.py
Configuration management using environment variables and config file
"""

import os
from pathlib import Path
from functools import lru_cache
from typing import Optional
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings


def get_default_interface() -> str:
    """
    Get the default network interface for packet capture.
    Works on both Linux and Windows.

    Returns:
        Interface name suitable for scapy (e.g., 'lo', 'Ethernet', 'Wi-Fi')
    """
    import platform
    import subprocess
    from scapy.all import IFACES

    system = platform.system().lower()

    # Try to detect available interfaces using scapy
    try:
        if ifaces:
            # Try loopback first (works on both platforms)
            for name in ["lo", "lo0", "Loopback"]:
                return "lo"
            if "lo0" in ifaces:  # macOS
                return "lo0"
            if "Loopback" in ifaces:  # Windows
                return "Loopback"
            # Return first available interface
            return list(ifaces.keys())[0]
    except Exception:
        pass

    # Fallback: detect based on platform
    if system == "windows":
        # Try to detect Windows interfaces via netsh
        try:
            result = subprocess.run(
                ["netsh", "interface", "show", "interface"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            # Look for common interface names
            for line in result.stdout.split("\n"):
                if "Loopback" in line:
                    return "Loopback"
                if "Ethernet" in line:
                    return "Ethernet"
                if "Wi-Fi" in line:
                    return "Wi-Fi"
        except Exception:
            pass
        return "Loopback"  # Windows almost always has this

    elif system == "darwin":  # macOS
        return "lo0"

    else:  # Linux
        # Try common Linux interface names
        try:
            result = subprocess.run(
                ["ip", "link", "show"], capture_output=True, text=True, timeout=5
            )
            for line in result.stdout.split("\n"):
                if ": lo:" in line:
                    return "lo"
                if ": eth" in line:
                    return "eth0"
                if ": enp" in line:
                    return "enp0s3"
                if ": wlan" in line:
                    return "wlan0"
        except Exception:
            pass
        return "lo"


class DatabaseConfig(BaseModel):
    """Database configuration"""

    path: str = "nids.db"
    retention_days: int = 14
    wal_mode: bool = True
    busy_timeout: int = 5000


class CaptureConfig(BaseModel):
    """Packet capture configuration"""

    interface: str = "wlan0"  # "auto" = detect automatically, or specify interface name
    bpf_filter: str = "ip and (tcp or udp or icmp)"
    queue_maxsize: int = 1000
    buffer_size: int = 65535
    promiscuous: bool = True

    def get_interface(self) -> str:
        """Get actual interface name, auto-detecting if needed"""
        if self.interface and self.interface != "auto":
            return self.interface
        return get_default_interface()


def get_default_interface() -> str:
    """
    Get the default network interface for packet capture.
    Works on both Linux and Windows.

    Returns:
        Interface name suitable for scapy (e.g., 'lo', 'Ethernet', 'Wi-Fi')
    """
    import platform
    import subprocess
    from scapy.all import IFACES

    system = platform.system().lower()

    # Try to detect available interfaces using scapy
    try:
        if ifaces:
            # Try loopback first (works on both platforms)
            for name in ["lo", "lo0", "Loopback"]:
                return "lo"
            if "lo0" in ifaces:  # macOS
                return "lo0"
            if "Loopback" in ifaces:  # Windows
                return "Loopback"
            # Return first available interface
            return list(ifaces.keys())[0]
    except Exception:
        pass

    # Fallback: detect based on platform
    if system == "windows":
        # Try to detect Windows interfaces via netsh
        try:
            result = subprocess.run(
                ["netsh", "interface", "show", "interface"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            # Look for common interface names
            for line in result.stdout.split("\n"):
                if "Loopback" in line:
                    return "Loopback"
                if "Ethernet" in line:
                    return "Ethernet"
                if "Wi-Fi" in line:
                    return "Wi-Fi"
        except Exception:
            pass
        return "Loopback"  # Windows almost always has this

    elif system == "darwin":  # macOS
        return "lo0"

    else:  # Linux
        # Try common Linux interface names
        try:
            result = subprocess.run(
                ["ip", "link", "show"], capture_output=True, text=True, timeout=5
            )
            for line in result.stdout.split("\n"):
                if ": lo:" in line:
                    return "lo"
                if ": eth" in line:
                    return "eth0"
                if ": enp" in line:
                    return "enp0s3"
                if ": wlan" in line:
                    return "wlan0"
        except Exception:
            pass
        return "lo"


class RateDetectorConfig(BaseModel):
    """Rate-based detector configuration"""

    port_scan_threshold: int = 20
    port_scan_window_sec: int = 10
    brute_force_threshold: int = 15
    brute_force_window_sec: int = 30
    syn_flood_threshold: int = 200
    syn_flood_window_sec: int = 5
    icmp_flood_threshold: int = 100
    icmp_flood_window_sec: int = 5
    host_sweep_threshold: int = 10
    host_sweep_window_sec: int = 15
    dns_flood_threshold: int = 50
    dns_flood_window_sec: int = 5
    exfil_threshold_bytes: int = 5_000_000
    exfil_window_sec: int = 60
    cooldown_sec: int = 60


class YaraConfig(BaseModel):
    """YARA engine configuration"""

    rules_file: str = "nids_rules.yar"
    enabled: bool = True
    timeout_ms: int = 1000
    max_payload_size: int = 1024 * 1024  # 1MB
    gating_enabled: bool = True
    gating_ports: list[int] = Field(
        default_factory=lambda: [22, 23, 25, 80, 443, 445, 3306, 3389, 5432, 8080]
    )


class ReputationConfig(BaseModel):
    """Reputation/Threat Intel configuration"""

    provider: str = "abuseipdb"
    enabled: bool = True
    abuseipdb_api_key: Optional[str] = None
    cache_ttl_sec: int = 3600
    timeout_sec: int = 2
    max_retries: int = 2
    min_severity_for_check: str = "medium"


class CorrelatorConfig(BaseModel):
    """Alert correlator configuration"""

    dedup_window_sec: int = 300
    score_weights: dict = Field(
        default_factory=lambda: {"rate": 30, "yara": 50, "reputation": 40}
    )
    severity_thresholds: dict = Field(
        default_factory=lambda: {"critical": 100, "high": 70, "medium": 40, "low": 10}
    )


class ApiConfig(BaseModel):
    """API server configuration"""

    host: str = "0.0.0.0"
    port: int = 8000
    debug: bool = False
    cors_origins: list[str] = Field(default_factory=lambda: ["*"])


class RuntimeConfig(BaseModel):
    """Runtime profile configuration"""

    profile: str = "lite"  # lite or enhanced
    enable_yara: bool = True
    enable_reputation: bool = True
    enable_ml: bool = False
    max_workers: int = 2
    log_level: str = "INFO"


class Settings(BaseSettings):
    """Main application settings"""

    app_name: str = "NIDS"
    version: str = "1.0.0"
    environment: str = "production"

    database: DatabaseConfig = Field(default_factory=DatabaseConfig)
    capture: CaptureConfig = Field(default_factory=CaptureConfig)
    rate_detector: RateDetectorConfig = Field(default_factory=RateDetectorConfig)
    yara: YaraConfig = Field(default_factory=YaraConfig)
    reputation: ReputationConfig = Field(default_factory=ReputationConfig)
    correlator: CorrelatorConfig = Field(default_factory=CorrelatorConfig)
    api: ApiConfig = Field(default_factory=ApiConfig)
    runtime: RuntimeConfig = Field(default_factory=RuntimeConfig)

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        env_nested_delimiter = "__"


@lru_cache()
def get_settings() -> Settings:
    """Get cached settings instance"""
    return Settings()
