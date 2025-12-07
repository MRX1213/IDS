"""
Configuration Management for IDS
"""
import json
from pathlib import Path
from typing import Dict, Any, Optional


class IDSConfig:
    """IDS Configuration Manager"""
    
    DEFAULT_CONFIG = {
        "detection": {
            "syn_scan_window": 10,
            "syn_scan_threshold": 5,
            "port_scan_window": 60,
            "port_scan_threshold": 10,
            "dos_window": 5,
            "dos_threshold": 100,
            "icmp_flood_window": 10,
            "icmp_flood_threshold": 50,
            "anomaly_z_threshold": 3.0,
            "suspicious_ports": {
                23: "Telnet (unencrypted)",
                135: "RPC",
                139: "NetBIOS",
                445: "SMB",
                1433: "MSSQL",
                3306: "MySQL",
                3389: "RDP",
                5432: "PostgreSQL",
                5900: "VNC",
                8080: "HTTP Proxy",
                4444: "Metasploit",
                31337: "Back Orifice"
            }
        },
        "output_dir": "outputs",
        "dashboard": {
            "host": "127.0.0.1",
            "port": 5000,
            "refresh_interval": 2
        },
        "logging": {
            "level": "INFO",
            "file": "ids.log"
        }
    }
    
    def __init__(self, config_file: Optional[Path] = None):
        self.config_file = config_file or Path("ids_config.json")
        self.config = self._load_config()
    
    def _load_config(self) -> Dict[str, Any]:
        """Load configuration from file or use defaults"""
        if self.config_file.exists():
            try:
                with self.config_file.open("r") as f:
                    file_config = json.load(f)
                    # Merge with defaults
                    config = self.DEFAULT_CONFIG.copy()
                    config = self._deep_merge(config, file_config)
                    return config
            except Exception as e:
                print(f"Error loading config file: {e}. Using defaults.")
                return self.DEFAULT_CONFIG.copy()
        else:
            # Create default config file
            self.save_config(self.DEFAULT_CONFIG)
            return self.DEFAULT_CONFIG.copy()
    
    def _deep_merge(self, base: Dict, update: Dict) -> Dict:
        """Deep merge two dictionaries"""
        result = base.copy()
        for key, value in update.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = self._deep_merge(result[key], value)
            else:
                result[key] = value
        return result
    
    def save_config(self, config: Optional[Dict] = None):
        """Save configuration to file"""
        config_to_save = config or self.config
        try:
            with self.config_file.open("w") as f:
                json.dump(config_to_save, f, indent=2)
            print(f"Configuration saved to {self.config_file}")
        except Exception as e:
            print(f"Error saving config: {e}")
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value"""
        keys = key.split(".")
        value = self.config
        for k in keys:
            if isinstance(value, dict):
                value = value.get(k)
                if value is None:
                    return default
            else:
                return default
        return value
    
    def set(self, key: str, value: Any):
        """Set configuration value"""
        keys = key.split(".")
        config = self.config
        for k in keys[:-1]:
            if k not in config:
                config[k] = {}
            config = config[k]
        config[keys[-1]] = value
        self.save_config()

