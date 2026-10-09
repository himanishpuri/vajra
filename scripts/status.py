#!/usr/bin/env python3
"""
Vajra Status - Check pipeline status and show blocked IPs (ML Enhanced)
"""

import os
import json
import subprocess
from pathlib import Path
from datetime import datetime


def check_process(name: str) -> bool:
    """Check if a process is running"""
    # Without a shell, pgrep -f cannot match the shell running it
    return subprocess.run(["pgrep", "-f", name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0


def main():
    os.chdir(Path(__file__).resolve().parent.parent)
    print("=" * 60)
    print("Vajra Pipeline Status (ML Enhanced)")
    print("=" * 60)
    
    # Process status
    print("\n[Services]")
    services = [
        ("Suricata", "suricata"),
        ("Kafka", "kafka.Kafka"),
        ("Kafka Bridge", "vajra.pipeline.kafka_bridge"),
        ("SOAR Engine", "vajra.soar.engine"),
        ("Unified Logger", "vajra.pipeline.unified_logger"),
        ("Packet Inspector", "vajra.inspection.packet_inspector")
    ]
    
    for name, proc in services:
        status = "[OK] Running" if check_process(proc) else "[FAIL] Stopped"
        print(f"  {name}: {status}")
    
    # ML Models
    print("\n[ML Models]")
    ml_dir = Path("models")
    if ml_dir.exists():
        models = list(ml_dir.glob("*.pkl")) + list(ml_dir.glob("*.joblib"))
        print(f"  Total models: {len(models)}")
        for model in models:
            size = model.stat().st_size / 1024
            print(f"    - {model.name} ({size:.1f} KB)")
        if not models:
            print("    No models loaded (add .pkl or .joblib files)")
    else:
        print("  models/ directory not found")
    
    # Log files
    print("\n[Log Files]")
    logs = [
        ("logs/eve.json", "Suricata Alerts"),
        ("logs/ml_predictions.json", "ML Predictions"),
        ("logs/unified_events.json", "Unified Events"),
        ("logs/soar_actions.log", "SOAR Actions"),
        ("logs/blocked_ips.txt", "Blocked IPs"),
        ("logs/packet_inspector.json", "Packet Inspector"),
    ]
    
    for log, desc in logs:
        p = Path(log)
        if p.exists():
            size = p.stat().st_size
            size_str = f"{size / 1024:.1f} KB" if size > 1024 else f"{size} B"
            lines = sum(1 for _ in open(p)) if size > 0 else 0
            print(f"  {desc}: {size_str} ({lines} entries)")
        else:
            print(f"  {desc}: (not created)")
    
    # Blocked IPs
    print("\n[Blocked IPs]")
    blocked_file = Path("logs/blocked_ips.txt")
    if blocked_file.exists():
        ips = blocked_file.read_text().strip().split('\n')
        ips = [ip for ip in ips if ip]
        print(f"  Total: {len(ips)}")
        for ip in ips[:10]:
            print(f"    - {ip}")
        if len(ips) > 10:
            print(f"    ... and {len(ips) - 10} more")
    else:
        print("  No IPs blocked yet")
    
    # Recent Suricata alerts
    print("\n[Recent Suricata Alerts]")
    eve_file = Path("logs/eve.json")
    if eve_file.exists():
        alerts = []
        with open(eve_file, 'r') as f:
            for line in f:
                try:
                    event = json.loads(line)
                    if event.get("event_type") == "alert":
                        alerts.append(event)
                except:
                    pass
        
        print(f"  Total alerts: {len(alerts)}")
        for alert in alerts[-5:]:
            sig = alert.get("alert", {}).get("signature", "Unknown")[:40]
            src = alert.get("src_ip", "?")
            print(f"    - {sig} ({src})")
    else:
        print("  No alerts yet (eve.json not found)")
    
    # Recent ML Predictions
    print("\n[Recent ML Predictions]")
    ml_file = Path("logs/ml_predictions.json")
    if ml_file.exists():
        predictions = []
        with open(ml_file, 'r') as f:
            for line in f:
                try:
                    pred = json.loads(line)
                    if pred.get("is_threat"):
                        predictions.append(pred)
                except:
                    pass
        
        print(f"  Total threat predictions: {len(predictions)}")
        for pred in predictions[-5:]:
            model = pred.get("model_name", "?")
            threat = pred.get("threat_type", "?")
            conf = pred.get("confidence", 0) * 100
            print(f"    - [{model}] {threat} ({conf:.1f}%)")
    else:
        print("  No ML predictions yet")
    
    # Unified Events Summary
    print("\n[Unified Events Summary]")
    unified_file = Path("logs/unified_events.json")
    if unified_file.exists():
        event_counts = {
            'suricata_alert': 0,
            'ml_prediction': 0,
            'soar_action': 0,
            'packet_inspection': 0
        }
        threat_counts = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0
        }
        
        with open(unified_file, 'r') as f:
            for line in f:
                try:
                    event = json.loads(line)
                    etype = event.get("event_type", "")
                    tlevel = event.get("threat_level", "")
                    if etype in event_counts:
                        event_counts[etype] += 1
                    if tlevel in threat_counts:
                        threat_counts[tlevel] += 1
                except:
                    pass
        
        print("  By Source:")
        for src, count in event_counts.items():
            if count > 0:
                print(f"    - {src}: {count}")
        
        print("  By Threat Level:")
        for level, count in threat_counts.items():
            if count > 0:
                print(f"    {level}: {count}")
    else:
        print("  No unified events yet")
    
    # Reports
    print("\n[Attack Reports]")
    reports_dir = Path("logs/reports")
    if reports_dir.exists():
        reports = list(reports_dir.glob("*.json"))
        print(f"  Total reports: {len(reports)}")
        for report in sorted(reports)[-5:]:
            print(f"    - {report.name}")
    else:
        print("  No reports yet")
    
    print("\n" + "=" * 50)


if __name__ == "__main__":
    main()
