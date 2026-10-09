#!/usr/bin/env python3
"""
SOAR Engine - Simplified Security Orchestration and Automated Response

Consumes alerts from Kafka, evaluates threat severity, and blocks attackers.
Generates reports for all detected and blocked attacks.

Enhanced with ML model integration:
- Loads and runs ML models for additional threat detection
- Combines Suricata alerts with ML predictions
- Unified logging for all security events
"""

import ipaddress
import json
import time
import logging
import os
import subprocess
import shutil
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, asdict

# Kafka imports
try:
    from confluent_kafka import Consumer, KafkaError  # type: ignore
    KAFKA_AVAILABLE = True
except ImportError:
    KAFKA_AVAILABLE = False

# ML Model Manager imports
try:
    from vajra.ml.manager import get_model_manager, MLPrediction, MLModelManager
    ML_AVAILABLE = True
except (ImportError, AttributeError) as e:
    ML_AVAILABLE = False
    print(f"Note: ML Model Manager not available - {e}")
except Exception as e:
    ML_AVAILABLE = False
    print(f"Note: ML Model Manager error - {e}")

# Unified Logger imports
try:
    from vajra.pipeline.unified_logger import get_unified_logger, UnifiedLogger
    UNIFIED_LOGGER_AVAILABLE = True
except ImportError:
    UNIFIED_LOGGER_AVAILABLE = False

# Packet Inspector imports
try:
    from vajra.inspection.packet_inspector import PacketInspector, PacketFeatures
    PACKET_INSPECTOR_AVAILABLE = True
except ImportError:
    PACKET_INSPECTOR_AVAILABLE = False

# UBA Engine imports
try:
    from vajra.detection.uba import get_uba_engine, UBAEngine
    UBA_AVAILABLE = True
except ImportError:
    UBA_AVAILABLE = False

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('logs/soar_engine.log')
    ]
)
logger = logging.getLogger("soar_engine")


@dataclass
class ActionRecord:
    """Record of a SOAR action"""
    timestamp: str
    alert_id: str
    action: str
    target_ip: str
    signature: str
    severity: str
    result: str
    blocked: bool


class FirewallManager:
    """Manages iptables/nftables for blocking IPs"""

    NFT_RULESET = """table inet vajra
delete table inet vajra
table inet vajra {
    set blocked_ips {
        type ipv4_addr
    }
    set blocked_ips6 {
        type ipv6_addr
    }
    chain input {
        type filter hook input priority filter - 1; policy accept;
        ip saddr @blocked_ips drop
        ip6 saddr @blocked_ips6 drop
    }
    chain output {
        type filter hook output priority filter - 1; policy accept;
        ip daddr @blocked_ips drop
        ip6 daddr @blocked_ips6 drop
    }
}
"""
    
    def __init__(self, dry_run: bool = False, allowlist: Optional[List[str]] = None):
        self.dry_run = dry_run
        self.backend = self._detect_backend()
        self.allowlist = self._build_allowlist(allowlist or [])
        self.blocked_ips_file = Path("logs/blocked_ips.txt")
        self.blocked_ips = self._load_blocked_ips()
        if self.enforcing and self.backend == "nftables":
            self._setup_nftables()
        logger.info(f"Firewall backend: {self.backend}" + (" (dry run)" if dry_run else ""))
        logger.info(f"Allowlist: {', '.join(str(n) for n in self.allowlist)}")

    @property
    def enforcing(self) -> bool:
        """True when blocks are actually applied to the host firewall"""
        return not self.dry_run and self.backend != "none"

    def _nft_set(self, ip: str) -> str:
        """Choose the nftables set for an IP address"""
        return "blocked_ips6" if ipaddress.ip_address(ip).version == 6 else "blocked_ips"

    def _setup_nftables(self):
        """Create the nftables rules and restore saved blocks"""
        try:
            result = subprocess.run(["nft", "-f", "-"], input=self.NFT_RULESET, capture_output=True, text=True, timeout=5)
        except (OSError, subprocess.SubprocessError) as e:
            logger.error(f"Could not set up nftables: {e}")
            return
        if result.returncode != 0:
            logger.error(f"Could not set up nftables: {result.stderr.strip()}")
            return

        # Recreating the table empties the sets, so re-apply saved blocks
        saved_ips = self.blocked_ips
        self.blocked_ips = set()
        for ip in saved_ips:
            self.block_ip(ip, "Restored saved block")
        self._save_blocked_ips()
        logger.info(f"Restored {len(self.blocked_ips)} nftables blocks")

    def _build_allowlist(self, extra: List[str]) -> list:
        """Networks that must never be blocked: loopback, this host, its gateway and DNS resolvers"""
        entries = ["127.0.0.0/8", "::1/128"] + list(extra)
        env = os.environ.get("VAJRA_ALLOWLIST", "")
        entries += [e.strip() for e in env.split(",") if e.strip()]
        try:
            from vajra.common.network import get_local_ip, get_gateway_ip
            entries += [get_local_ip(), get_gateway_ip()]
        except Exception as e:
            logger.warning(f"Could not detect local addresses for the allowlist: {e}")
        try:
            for line in Path("/etc/resolv.conf").read_text().splitlines():
                parts = line.split()
                if len(parts) >= 2 and parts[0] == "nameserver":
                    entries.append(parts[1])
        except OSError:
            pass

        networks = []
        for entry in entries:
            try:
                network = ipaddress.ip_network(entry, strict=False)
            except ValueError:
                logger.warning(f"Ignoring invalid allowlist entry: {entry}")
                continue
            if network not in networks:
                networks.append(network)
        return networks

    def is_allowlisted(self, ip: str) -> bool:
        """Check whether an IP falls inside the allowlist"""
        try:
            address = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(address.version == n.version and address in n for n in self.allowlist)
    
    def _detect_backend(self) -> str:
        """Detect available firewall backend"""
        if shutil.which("nft"):
            return "nftables"
        elif shutil.which("iptables"):
            return "iptables"
        else:
            return "none"
    
    def _load_blocked_ips(self) -> set:
        """Load previously blocked IPs"""
        if self.blocked_ips_file.exists():
            return set(self.blocked_ips_file.read_text().strip().split('\n'))
        return set()
    
    def _save_blocked_ips(self):
        """Save blocked IPs to file"""
        self.blocked_ips_file.parent.mkdir(parents=True, exist_ok=True)
        self.blocked_ips_file.write_text('\n'.join(self.blocked_ips))
    
    def block_ip(self, ip: str, reason: str = "") -> bool:
        """Block an IP address"""
        if not ip:
            return False

        if self.is_allowlisted(ip):
            logger.warning(f"Not blocking allowlisted IP {ip} | Reason: {reason}")
            return False
        
        if ip in self.blocked_ips:
            logger.debug(f"IP {ip} already blocked")
            return True

        if not self.enforcing:
            logger.warning(f"Would block {ip} (not enforced: {'dry run' if self.dry_run else 'no firewall backend'}) | Reason: {reason}")
            return False
        
        success = False
        
        try:
            if self.backend == "nftables":
                # nftables
                cmd = ["nft", "add", "element", "inet", "vajra", self._nft_set(ip), f"{{ {ip} }}"]
                result = subprocess.run(cmd, capture_output=True, timeout=5)
                success = result.returncode == 0
                
            elif self.backend == "iptables":
                # iptables - add to INPUT and OUTPUT
                cmd1 = ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP", "-m", "comment", "--comment", f"Vajra: {reason[:50]}"]
                cmd2 = ["iptables", "-A", "OUTPUT", "-d", ip, "-j", "DROP"]
                
                r1 = subprocess.run(cmd1, capture_output=True, timeout=5)
                r2 = subprocess.run(cmd2, capture_output=True, timeout=5)
                success = r1.returncode == 0 or r2.returncode == 0

            if success:
                self.blocked_ips.add(ip)
                self._save_blocked_ips()
                logger.info(f"BLOCKED IP: {ip} | Reason: {reason}")
            else:
                logger.error(f"Failed to block IP: {ip}")
                
        except Exception as e:
            logger.error(f"Error blocking IP {ip}: {e}")
            success = False
        
        return success
    
    def unblock_ip(self, ip: str) -> bool:
        """Unblock an IP address"""
        if ip not in self.blocked_ips:
            return True
        
        try:
            if self.backend == "nftables":
                cmd = ["nft", "delete", "element", "inet", "vajra", self._nft_set(ip), f"{{ {ip} }}"]
                subprocess.run(cmd, capture_output=True, timeout=5)
            elif self.backend == "iptables":
                subprocess.run(["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"], capture_output=True, timeout=5)
                subprocess.run(["iptables", "-D", "OUTPUT", "-d", ip, "-j", "DROP"], capture_output=True, timeout=5)
            
            self.blocked_ips.discard(ip)
            self._save_blocked_ips()
            logger.info(f"Unblocked IP: {ip}")
            return True
            
        except Exception as e:
            logger.error(f"Error unblocking IP {ip}: {e}")
            return False


class ReportGenerator:
    """Generates attack reports"""
    
    def __init__(self, reports_dir: str = "logs/reports"):
        self.reports_dir = Path(reports_dir)
        self.reports_dir.mkdir(parents=True, exist_ok=True)
        self.actions: List[ActionRecord] = []
    
    def add_action(self, action: ActionRecord):
        """Add an action to the report"""
        self.actions.append(action)
        
        # Also append to actions log
        with open("logs/soar_actions.log", "a") as f:
            f.write(json.dumps(asdict(action)) + "\n")
    
    def generate_report(self, alert: Dict[str, Any], action: ActionRecord):
        """Generate a detailed report for an attack"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_file = self.reports_dir / f"report_{timestamp}_{alert.get('src_ip', 'unknown')}.json"
        
        report = {
            "report_id": f"RPT-{timestamp}",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "alert": alert,
            "action_taken": asdict(action),
            "analysis": {
                "attack_type": self._classify_attack(alert.get("signature", "")),
                "severity": alert.get("severity", "MEDIUM"),
                "source_ip": alert.get("src_ip", "unknown"),
                "destination_ip": alert.get("dest_ip", "unknown"),
                "protocol": alert.get("proto", "unknown"),
                "blocked": action.blocked
            },
            "recommendations": self._get_recommendations(alert)
        }
        
        report_file.write_text(json.dumps(report, indent=2))
        logger.info(f"Report generated: {report_file.name}")
        
        return report
    
    def _classify_attack(self, signature: str) -> str:
        """Classify attack type from signature"""
        sig_lower = signature.lower()
        
        if "sql" in sig_lower or "injection" in sig_lower:
            return "SQL Injection"
        elif "xss" in sig_lower or "script" in sig_lower:
            return "Cross-Site Scripting (XSS)"
        elif "traversal" in sig_lower or "path" in sig_lower or "../" in sig_lower:
            return "Path Traversal"
        elif "command" in sig_lower or "cmd" in sig_lower:
            return "Command Injection"
        elif "scan" in sig_lower or "recon" in sig_lower:
            return "Port Scan / Reconnaissance"
        elif "ddos" in sig_lower or "flood" in sig_lower:
            return "DDoS Attack"
        elif "brute" in sig_lower or "credential" in sig_lower:
            return "Credential Abuse"
        elif "c2" in sig_lower or "beacon" in sig_lower:
            return "C2 / Beaconing"
        elif "exfil" in sig_lower:
            return "Data Exfiltration"
        elif "dns" in sig_lower and "spoof" in sig_lower:
            return "DNS Spoofing"
        else:
            return "Unknown Attack"
    
    def _get_recommendations(self, alert: Dict[str, Any]) -> List[str]:
        """Get recommendations based on attack type"""
        attack_type = self._classify_attack(alert.get("signature", ""))
        
        recommendations = {
            "SQL Injection": [
                "Review and sanitize all user inputs",
                "Use parameterized queries",
                "Implement WAF rules for SQL injection"
            ],
            "Cross-Site Scripting (XSS)": [
                "Encode all user output",
                "Implement Content Security Policy",
                "Use HTTPOnly cookies"
            ],
            "Path Traversal": [
                "Validate and sanitize file paths",
                "Use chroot or containers",
                "Implement proper access controls"
            ],
            "Port Scan / Reconnaissance": [
                "Review exposed services",
                "Implement port knocking",
                "Monitor for follow-up attacks"
            ],
            "DDoS Attack": [
                "Enable rate limiting",
                "Use CDN/DDoS protection",
                "Scale infrastructure if needed"
            ],
            "Credential Abuse": [
                "Implement account lockout",
                "Enable MFA",
                "Monitor for compromised credentials"
            ]
        }
        
        return recommendations.get(attack_type, ["Review security posture", "Monitor for additional attacks"])


class SOAREngine:
    """Main SOAR Engine - consumes Kafka alerts and takes action
    
    Enhanced with ML integration:
    - Loads ML models for additional threat detection
    - Combines Suricata alerts with ML predictions
    - Unified logging for all security events
    """
    
    def __init__(
        self,
        kafka_broker: str = "localhost:9092",
        topic: str = "suricata-alerts",
        group_id: str = "soar-engine",
        ml_models_dir: str = "models",
        enable_ml: bool = True,
        enable_packet_inspection: bool = False,
        network_interface: str = None,
        dry_run: bool = False,
        allowlist: Optional[List[str]] = None
    ):
        self.topic = topic
        self.firewall = FirewallManager(dry_run=dry_run, allowlist=allowlist)
        self.reporter = ReportGenerator()
        self.processed_alerts = 0
        self.blocked_count = 0
        self.ml_threats_detected = 0
        
        # ML Model Manager
        self.ml_enabled = enable_ml and ML_AVAILABLE
        self.model_manager: Optional[MLModelManager] = None
        if self.ml_enabled:
            self.model_manager = get_model_manager()
            self._load_ml_models(ml_models_dir)
            # Register callback for ML predictions
            self.model_manager.register_callback(self._on_ml_prediction)
            logger.info("ML Model Manager initialized")
        
        # Unified Logger
        self.unified_logger: Optional[UnifiedLogger] = None
        if UNIFIED_LOGGER_AVAILABLE:
            self.unified_logger = get_unified_logger()
            self.unified_logger.start()
            logger.info("Unified Logger initialized")
        
        # Packet Inspector (optional, for deep packet inspection)
        self.packet_inspector: Optional[PacketInspector] = None
        self.inspector_thread: Optional[threading.Thread] = None
        if enable_packet_inspection and PACKET_INSPECTOR_AVAILABLE:
            try:
                self.packet_inspector = PacketInspector(
                    interface=network_interface,
                    ml_enabled=self.ml_enabled
                )
                self.packet_inspector.register_threat_callback(self._on_packet_threat)
                logger.info("Packet Inspector initialized")
            except Exception as e:
                logger.warning(f"Could not initialize Packet Inspector: {e}")
                logger.warning("Deep packet inspection will be disabled")
                self.packet_inspector = None
        
        # UBA Engine (User Behavior Analytics)
        self.uba_engine: Optional[UBAEngine] = None
        if UBA_AVAILABLE:
            try:
                self.uba_engine = get_uba_engine()
                logger.info("UBA Engine initialized for insider threat detection")
            except Exception as e:
                logger.warning(f"Could not initialize UBA Engine: {e}")
        
        # Initialize Kafka consumer
        if KAFKA_AVAILABLE:
            self.consumer = Consumer({
                'bootstrap.servers': kafka_broker,
                'group.id': group_id,
                'auto.offset.reset': 'latest',
                'enable.auto.commit': True,
            })
            self.consumer.subscribe([topic])
            logger.info(f"Kafka consumer subscribed to {topic}")
        else:
            self.consumer = None
            logger.warning("Kafka not available - using file-based fallback")
    
    def _load_ml_models(self, models_dir: str):
        """Load ML models from directory"""
        models_path = Path(models_dir)
        if not models_path.exists():
            models_path.mkdir(parents=True, exist_ok=True)
            logger.info(f"Created models directory: {models_dir}")
            return
        
        # Auto-load any .pkl or .joblib files
        for model_file in models_path.glob("*.pkl"):
            name = model_file.stem
            # Determine model type from filename
            model_type = "custom"
            if "insider" in name.lower():
                model_type = "insider_threat"
            elif "anomaly" in name.lower():
                model_type = "anomaly"
            elif "ddos" in name.lower():
                model_type = "ddos"
            
            self.model_manager.load_model(name, str(model_file), model_type)
        
        for model_file in models_path.glob("*.joblib"):
            name = model_file.stem
            model_type = "custom"
            if "insider" in name.lower():
                model_type = "insider_threat"
            elif "anomaly" in name.lower():
                model_type = "anomaly"
            elif "ddos" in name.lower():
                model_type = "ddos"
            
            self.model_manager.load_model(name, str(model_file), model_type)
        
        logger.info(f"Loaded {len(self.model_manager.models)} ML models")
    
    def _on_ml_prediction(self, prediction: MLPrediction):
        """Callback when ML model makes a threat prediction"""
        if not prediction.is_threat:
            return
        
        self.ml_threats_detected += 1
        
        logger.warning(
            f"ML THREAT DETECTED: {prediction.threat_type} | "
            f"Model: {prediction.model_name} | "
            f"Confidence: {prediction.confidence:.2%}"
        )
        
        # Log to unified logger
        if self.unified_logger:
            self.unified_logger.log_ml_prediction(asdict(prediction))
        
        # Check if we should block based on ML prediction
        src_ip = prediction.features_used.get('src_ip', '')
        if src_ip and prediction.confidence >= 0.8:
            # High confidence ML prediction - consider blocking
            blocked = self.firewall.block_ip(
                src_ip, 
                reason=f"ML-{prediction.model_name}: {prediction.threat_type}"
            )
            if blocked:
                self.blocked_count += 1
                logger.info(f"Blocked {src_ip} based on ML prediction")
    
    def _on_packet_threat(self, features: 'PacketFeatures', prediction: Optional[MLPrediction]):
        """Callback when packet inspector detects a threat"""
        if prediction and prediction.is_threat:
            logger.warning(
                f"PACKET THREAT: {features.src_ip}:{features.src_port} -> "
                f"{features.dst_ip}:{features.dst_port} | "
                f"ML: {prediction.threat_type} ({prediction.confidence:.2%})"
            )
            
            # Block if high confidence
            if prediction.confidence >= 0.8:
                self.firewall.block_ip(
                    features.src_ip,
                    reason=f"Packet-ML: {prediction.threat_type}"
                )
    
    def run_ml_on_alert(self, alert: Dict[str, Any]) -> List[MLPrediction]:
        """Run ML models on a Suricata alert"""
        if not self.ml_enabled or not self.model_manager:
            return []
        
        # Extract features from alert
        features = {
            'src_ip': alert.get('src_ip', ''),
            'dst_ip': alert.get('dest_ip', ''),
            'src_port': alert.get('src_port', 0),
            'dst_port': alert.get('dest_port', 0),
            'protocol': alert.get('proto', ''),
            'timestamp': alert.get('timestamp', ''),
            'signature': alert.get('signature', ''),
            'severity': alert.get('severity', ''),
            'category': alert.get('category', ''),
            'app_proto': alert.get('app_proto', ''),
            # Flow data if available
            'bytes_sent': alert.get('flow', {}).get('bytes_toserver', 0),
            'bytes_received': alert.get('flow', {}).get('bytes_toclient', 0),
        }
        
        # Run all models
        predictions = self.model_manager.predict_all(features, data_type="flow")
        
        return list(predictions.values())
    
    def should_block(self, alert: Dict[str, Any]) -> bool:
        """Determine if alert should trigger a block"""
        severity = alert.get("severity", "LOW")
        signature = alert.get("signature", "").lower()
        
        # Always block critical/high severity
        if severity in ("CRITICAL", "HIGH"):
            return True
        
        # Block specific attack types regardless of severity
        block_keywords = [
            "vajra", "sql injection", "xss", "command injection",
            "traversal", "brute force", "ddos", "flood", "c2",
            "exfil", "spoof", "scan"
        ]
        
        for keyword in block_keywords:
            if keyword in signature:
                return True
        
        return False
    
    def _action_result(self, should_block: bool, blocked: bool, src_ip: str) -> str:
        """Describe the outcome of a SOAR decision"""
        if not should_block or blocked:
            return "success"
        if self.firewall.is_allowlisted(src_ip):
            return "allowlisted"
        if not self.firewall.enforcing:
            return "not_enforced"
        return "failed"

    def process_alert(self, alert: Dict[str, Any]):
        """Process a single alert with ML enhancement"""
        self.processed_alerts += 1
        
        src_ip = alert.get("src_ip", "")
        signature = alert.get("signature", "Unknown")
        severity = alert.get("severity", "MEDIUM")
        
        logger.info(f"Processing alert: {signature} from {src_ip} [{severity}]")
        
        # UBA Analysis
        # Extract user information from alert if available
        uba_alert = None
        if self.uba_engine and alert.get('user_id'):
            # Convert alert to UBA event format
            uba_event = {
                'user_id': alert.get('user_id'),
                'event_type': alert.get('event_type', 'alert'),
                'timestamp': alert.get('timestamp', datetime.now(timezone.utc).isoformat()),
                'src_ip': src_ip,
                'dest_ip': alert.get('dest_ip', ''),
                'signature': signature
            }
            uba_alert = self.uba_engine.update_user_state(uba_event)
            
            if uba_alert:
                logger.warning(f"  UBA Alert: {uba_alert.alert_type} - {uba_alert.threat_indicator}")
        
        # Run ML models on the alert for additional analysis
        ml_predictions = []
        ml_threat_detected = False
        if self.ml_enabled:
            ml_predictions = self.run_ml_on_alert(alert)
            for pred in ml_predictions:
                if pred and pred.is_threat:
                    ml_threat_detected = True
                    logger.info(f"  ML prediction: {pred.model_name} -> {pred.threat_type} ({pred.confidence:.2%})")
        
        # Determine action (combine Suricata + ML + UBA)
        should_block = self.should_block(alert)
        
        # Also block if ML detected high-confidence threat
        if ml_threat_detected and any(p.confidence >= 0.75 for p in ml_predictions if p and p.is_threat):
            should_block = True
            logger.info("  ML high-confidence threat - upgrading to block")
        
        # Also block if UBA detected critical insider threat
        if uba_alert and uba_alert.severity in ("HIGH", "CRITICAL"):
            should_block = True
            logger.info(f"  UBA critical threat - upgrading to block: {uba_alert.threat_indicator}")
        
        blocked = False
        
        if should_block and src_ip:
            blocked = self.firewall.block_ip(src_ip, reason=signature)
            if blocked:
                self.blocked_count += 1
        
        # Create action record
        action = ActionRecord(
            timestamp=datetime.now(timezone.utc).isoformat(),
            alert_id=alert.get("alert_id", f"alert-{self.processed_alerts}"),
            action="BLOCK_IP" if should_block else "LOG_ONLY",
            target_ip=src_ip,
            signature=signature,
            severity=severity,
            result=self._action_result(should_block, blocked, src_ip),
            blocked=blocked
        )
        
        self.reporter.add_action(action)
        
        # Log to unified logger
        if self.unified_logger:
            self.unified_logger.log_soar_action(asdict(action))
        
        # Generate report for blocked attacks
        if blocked:
            report = self.reporter.generate_report(alert, action)
            
            # Add ML predictions to report if available
            if ml_predictions and report:
                report['ml_analysis'] = [
                    {
                        'model': p.model_name,
                        'prediction': p.prediction,
                        'confidence': p.confidence,
                        'threat_type': p.threat_type,
                        'is_threat': p.is_threat
                    }
                    for p in ml_predictions if p
                ]
            
            # Add UBA analysis to report if available
            if uba_alert and report:
                report['uba_analysis'] = {
                    'alert_type': uba_alert.alert_type,
                    'severity': uba_alert.severity,
                    'threat_indicator': uba_alert.threat_indicator,
                    'confidence': uba_alert.confidence,
                    'user_profile': uba_alert.profile_snapshot
                }
    
    def start_packet_inspector(self):
        """Start packet inspector in background thread"""
        if self.packet_inspector:
            self.inspector_thread = threading.Thread(
                target=self.packet_inspector.start,
                daemon=True
            )
            self.inspector_thread.start()
            logger.info("Packet Inspector started in background")
    
    def stop_packet_inspector(self):
        """Stop packet inspector"""
        if self.packet_inspector:
            self.packet_inspector.stop()
            logger.info("Packet Inspector stopped")
    
    def run_kafka(self):
        """Run with Kafka consumer"""
        logger.info("Starting SOAR Engine (Kafka mode)")
        
        try:
            while True:
                msg = self.consumer.poll(timeout=1.0)
                
                if msg is None:
                    continue
                
                if msg.error():
                    if msg.error().code() == KafkaError._PARTITION_EOF:
                        continue
                    logger.error(f"Kafka error: {msg.error()}")
                    continue
                
                try:
                    alert = json.loads(msg.value().decode('utf-8'))
                    self.process_alert(alert)
                except json.JSONDecodeError as e:
                    logger.error(f"Invalid JSON: {e}")
                except Exception as e:
                    logger.error(f"Error processing message: {e}")
                    
        except KeyboardInterrupt:
            logger.info("Shutting down...")
        finally:
            if self.consumer:
                self.consumer.close()
    
    def run_file(self, eve_path: str = "logs/eve.json"):
        """Run with file-based input (fallback when Kafka not available)"""
        logger.info(f"Starting SOAR Engine (file mode) - watching {eve_path}")
        
        eve_file = Path(eve_path)
        last_position = 0
        
        # Wait for file
        while not eve_file.exists():
            logger.info(f"Waiting for {eve_path}...")
            time.sleep(2)
        
        last_position = eve_file.stat().st_size
        
        try:
            while True:
                current_size = eve_file.stat().st_size
                
                if current_size < last_position:
                    last_position = 0
                
                if current_size > last_position:
                    with open(eve_file, 'r') as f:
                        f.seek(last_position)
                        
                        for line in f:
                            try:
                                event = json.loads(line.strip())
                                if event.get("event_type") == "alert":
                                    alert = self._parse_eve_alert(event)
                                    self.process_alert(alert)
                            except:
                                pass
                        
                        last_position = f.tell()
                
                time.sleep(0.1)
                
        except KeyboardInterrupt:
            logger.info("Shutting down...")
    
    def _parse_eve_alert(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Parse eve.json alert format"""
        alert_data = event.get("alert", {})
        
        severity_map = {1: "CRITICAL", 2: "HIGH", 3: "MEDIUM", 4: "LOW"}
        
        return {
            "alert_id": f"alert-{event.get('timestamp', '')}-{alert_data.get('signature_id', 0)}",
            "timestamp": event.get("timestamp", ""),
            "signature": alert_data.get("signature", "Unknown"),
            "severity": severity_map.get(alert_data.get("severity", 3), "MEDIUM"),
            "src_ip": event.get("src_ip", ""),
            "dest_ip": event.get("dest_ip", ""),
            "src_port": event.get("src_port", 0),
            "dest_port": event.get("dest_port", 0),
            "proto": event.get("proto", ""),
            "category": alert_data.get("category", ""),
            "app_proto": event.get("app_proto", ""),
            "flow": event.get("flow", {}),
            "http": event.get("http", {}),
            "dns": event.get("dns", {}),
        }
    
    def run(self):
        """Main run method - auto-detect mode"""
        logger.info("=" * 50)
        logger.info("Vajra SOAR Engine Starting (ML Enhanced)")
        logger.info(f"  Firewall: {self.firewall.backend}")
        logger.info(f"  Kafka: {'available' if KAFKA_AVAILABLE and self.consumer else 'not available'}")
        logger.info(f"  ML Models: {'enabled' if self.ml_enabled else 'disabled'}")
        if self.ml_enabled and self.model_manager:
            logger.info(f"  Loaded Models: {list(self.model_manager.models.keys())}")
        logger.info(f"  Unified Logger: {'enabled' if self.unified_logger else 'disabled'}")
        logger.info(f"  Packet Inspector: {'enabled' if self.packet_inspector else 'disabled'}")
        logger.info("=" * 50)
        
        # Start packet inspector if enabled
        if self.packet_inspector:
            self.start_packet_inspector()
        
        try:
            if self.consumer:
                self.run_kafka()
            else:
                self.run_file()
        finally:
            # Cleanup
            if self.packet_inspector:
                self.stop_packet_inspector()
            if self.unified_logger:
                self.unified_logger.stop()
        
        # Print statistics
        logger.info("=" * 50)
        logger.info("SOAR Engine Statistics:")
        logger.info(f"  Processed alerts: {self.processed_alerts}")
        logger.info(f"  Blocked IPs: {self.blocked_count}")
        logger.info(f"  ML threats detected: {self.ml_threats_detected}")
        if self.ml_enabled and self.model_manager:
            ml_stats = self.model_manager.get_stats()
            logger.info(f"  ML predictions: {ml_stats.get('total_predictions', 0)}")
        if self.unified_logger:
            unified_stats = self.unified_logger.get_stats()
            logger.info(f"  Unified events: {unified_stats.get('total_events', 0)}")
        logger.info("=" * 50)


def main():
    import argparse
    parser = argparse.ArgumentParser(description="SOAR Engine with ML Integration")
    parser.add_argument("--broker", default="localhost:9092", help="Kafka broker")
    parser.add_argument("--topic", default="suricata-alerts", help="Kafka topic")
    parser.add_argument("--eve", default="logs/eve.json", help="Eve file for fallback mode")
    parser.add_argument("--file-mode", action="store_true", help="Force file-based mode")
    parser.add_argument("--ml-models-dir", default="models", help="Directory containing ML models")
    parser.add_argument("--no-ml", action="store_true", help="Disable ML predictions")
    parser.add_argument("--packet-inspection", action="store_true", help="Enable deep packet inspection with Scapy")
    parser.add_argument("--interface", help="Network interface for packet inspection")
    parser.add_argument("--dry-run", action="store_true", help="Log block decisions without changing the firewall")
    parser.add_argument("--allow", action="append", default=[], metavar="CIDR",
                       help="Address or network that must never be blocked (repeatable)")
    parser.add_argument("--load-model", help="Load a specific model file")
    parser.add_argument("--model-name", default="custom", help="Name for the loaded model")
    parser.add_argument("--model-type", default="custom", 
                       choices=['insider_threat', 'anomaly', 'ddos', 'custom'],
                       help="Type of model being loaded")
    args = parser.parse_args()
    
    os.makedirs("logs", exist_ok=True)
    os.makedirs("logs/reports", exist_ok=True)
    os.makedirs("models", exist_ok=True)
    
    # Create engine
    engine = SOAREngine(
        kafka_broker=args.broker,
        topic=args.topic,
        ml_models_dir=args.ml_models_dir,
        enable_ml=not args.no_ml,
        enable_packet_inspection=args.packet_inspection,
        network_interface=args.interface,
        dry_run=args.dry_run,
        allowlist=args.allow
    )
    
    # Load specific model if requested
    if args.load_model and engine.ml_enabled:
        engine.model_manager.load_model(
            args.model_name,
            args.load_model,
            args.model_type
        )
    
    # Run engine
    if args.file_mode:
        engine.run_file(args.eve)
    else:
        engine.run()


if __name__ == "__main__":
    main()
