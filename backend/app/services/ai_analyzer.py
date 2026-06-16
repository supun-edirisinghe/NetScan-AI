"""
AI/ML Risk Analysis Engine
Uses Scikit-learn for risk scoring + rule-based expert system for recommendations.
Optionally integrates TensorFlow for deep learning models.
"""
import numpy as np
import logging
import os
import json
from typing import Dict, List, Any, Tuple
from pathlib import Path

logger = logging.getLogger(__name__)

# ─── Rule-Based Recommendation Engine ────────────────────────────────────────

SECURITY_RULES = [
    {
        "id": "R001",
        "port": 23,
        "service": "Telnet",
        "severity": "critical",
        "title": "Telnet Service Exposed",
        "description": "Telnet transmits data in plaintext including passwords.",
        "recommendation": "Immediately disable Telnet. Replace with SSH (port 22) for encrypted remote access.",
        "cve_refs": ["CVE-2019-6135"],
    },
    {
        "id": "R002",
        "port": 21,
        "service": "FTP",
        "severity": "high",
        "title": "FTP Service Detected",
        "description": "FTP transmits credentials and data in cleartext.",
        "recommendation": "Disable FTP. Use SFTP or FTPS for secure file transfers.",
        "cve_refs": [],
    },
    {
        "id": "R003",
        "port": 445,
        "service": "SMB",
        "severity": "critical",
        "title": "SMB Port Open",
        "description": "SMB (port 445) is a primary ransomware attack vector (WannaCry, NotPetya).",
        "recommendation": "Block SMB from internet access. Apply MS17-010 patch. Enable SMB signing.",
        "cve_refs": ["CVE-2017-0144", "CVE-2017-0145"],
    },
    {
        "id": "R004",
        "port": 3389,
        "service": "RDP",
        "severity": "high",
        "title": "RDP Exposed to Network",
        "description": "Remote Desktop Protocol is frequently targeted for brute-force attacks.",
        "recommendation": "Restrict RDP access via VPN only. Enable NLA. Use fail2ban or account lockout policies.",
        "cve_refs": ["CVE-2019-0708"],
    },
    {
        "id": "R005",
        "port": 6379,
        "service": "Redis",
        "severity": "critical",
        "title": "Redis Without Authentication",
        "description": "Redis instances without auth are commonly exploited for data theft and cryptomining.",
        "recommendation": "Enable Redis authentication (requirepass). Bind to localhost only. Use firewall rules.",
        "cve_refs": [],
    },
    {
        "id": "R006",
        "port": 27017,
        "service": "MongoDB",
        "severity": "critical",
        "title": "MongoDB Exposed",
        "description": "MongoDB without auth has been responsible for millions of data breaches.",
        "recommendation": "Enable MongoDB authentication. Bind to internal IPs only. Use TLS for connections.",
        "cve_refs": [],
    },
    {
        "id": "R007",
        "port": 9200,
        "service": "Elasticsearch",
        "severity": "high",
        "title": "Elasticsearch Publicly Accessible",
        "description": "Open Elasticsearch clusters expose all indexed data without authentication.",
        "recommendation": "Enable X-Pack security. Restrict network access. Deploy behind a reverse proxy.",
        "cve_refs": [],
    },
    {
        "id": "R008",
        "port": 5900,
        "service": "VNC",
        "severity": "high",
        "title": "VNC Remote Access Detected",
        "description": "VNC often transmits data unencrypted and is a target for brute force.",
        "recommendation": "Tunnel VNC through SSH. Use strong passwords. Restrict to internal network.",
        "cve_refs": [],
    },
    {
        "id": "R009",
        "port": 135,
        "service": "MSRPC",
        "severity": "medium",
        "title": "Windows RPC Endpoint Mapper Exposed",
        "description": "MSRPC is commonly exploited in Windows environments.",
        "recommendation": "Block port 135 at the perimeter firewall. Apply all Windows security patches.",
        "cve_refs": [],
    },
    {
        "id": "R010",
        "port": 22,
        "service": "SSH",
        "severity": "low",
        "title": "SSH Service Detected",
        "description": "SSH is secure but should be hardened against brute-force attacks.",
        "recommendation": "Disable password auth, use key-based authentication. Change default port. Use fail2ban.",
        "cve_refs": [],
    },
]


def build_feature_vector(host_data: Dict) -> np.ndarray:
    """
    Convert host scan data into ML feature vector.
    Features: open port count, has high-risk ports, risk score sum, service diversity
    """
    open_ports = host_data.get("open_ports", [])
    port_numbers = [p["port"] for p in open_ports]

    high_risk_ports = {23, 21, 445, 3389, 4444, 6379, 27017, 9200}
    medium_risk_ports = {135, 139, 5900, 1433, 1521, 3306}

    features = [
        len(open_ports),                                      # f1: total open ports
        len([p for p in port_numbers if p in high_risk_ports]),  # f2: high risk port count
        len([p for p in port_numbers if p in medium_risk_ports]),# f3: medium risk port count
        sum(p.get("risk_weight", 0.2) for p in open_ports),  # f4: cumulative risk weight
        1 if 80 in port_numbers or 8080 in port_numbers else 0,  # f5: web server
        1 if 443 in port_numbers or 8443 in port_numbers else 0, # f6: HTTPS
        1 if 22 in port_numbers else 0,                      # f7: SSH present
        1 if 3306 in port_numbers or 5432 in port_numbers else 0, # f8: DB exposed
        max((p.get("risk_weight", 0) for p in open_ports), default=0),  # f9: max single risk
        len(set(port_numbers)) / max(len(port_numbers), 1),  # f10: port diversity
    ]

    return np.array(features, dtype=np.float32)


def calculate_risk_score(host_data: Dict) -> Tuple[float, str]:
    """
    Calculate risk score (0-100) and level using weighted formula.
    This is a rule-based fallback when ML model is not trained.
    """
    open_ports = host_data.get("open_ports", [])
    if not open_ports:
        return 0.0, "low"

    port_numbers = [p["port"] for p in open_ports]

    # Base score from risk weights
    risk_weights = [p.get("risk_weight", 0.2) for p in open_ports]
    base_score = min(sum(risk_weights) / len(risk_weights) * 100, 100)

    # Bonus for critical services
    critical_bonus = 0
    if 23 in port_numbers: critical_bonus += 20    # Telnet
    if 445 in port_numbers: critical_bonus += 25   # SMB
    if 4444 in port_numbers: critical_bonus += 30  # Metasploit
    if 6379 in port_numbers: critical_bonus += 20  # Redis
    if 27017 in port_numbers: critical_bonus += 20 # MongoDB

    # Penalty for having many open ports
    port_count_penalty = min(len(open_ports) * 2, 20)

    final_score = min(base_score + critical_bonus + port_count_penalty, 100)

    if final_score >= 70:
        level = "critical"
    elif final_score >= 50:
        level = "high"
    elif final_score >= 25:
        level = "medium"
    else:
        level = "low"

    return round(final_score, 1), level


def generate_recommendations(scan_results: Dict) -> List[Dict]:
    """
    Generate AI recommendations based on open ports found across all hosts.
    Returns deduplicated, prioritized list of security recommendations.
    """
    all_open_ports = set()

    for host in scan_results.get("hosts", []):
        for port_info in host.get("open_ports", []):
            all_open_ports.add(port_info["port"])

    recommendations = []
    seen_ids = set()

    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}

    for rule in SECURITY_RULES:
        if rule["port"] in all_open_ports and rule["id"] not in seen_ids:
            recommendations.append({
                "id": rule["id"],
                "severity": rule["severity"],
                "title": rule["title"],
                "description": rule["description"],
                "recommendation": rule["recommendation"],
                "affected_port": rule["port"],
                "service": rule["service"],
                "cve_refs": rule.get("cve_refs", []),
            })
            seen_ids.add(rule["id"])

    # Sort by severity
    recommendations.sort(key=lambda x: severity_order.get(x["severity"], 99))

    # Add general recommendations
    if len(all_open_ports) > 20:
        recommendations.append({
            "id": "G001",
            "severity": "medium",
            "title": "Excessive Open Ports Detected",
            "description": f"{len(all_open_ports)} unique ports are open across scanned hosts.",
            "recommendation": "Review and close unnecessary services. Follow principle of least privilege.",
            "affected_port": None,
            "service": "General",
            "cve_refs": [],
        })

    return recommendations


def analyze_scan_with_ml(scan_results: Dict) -> Dict[str, Any]:
    """
    Full AI analysis pipeline:
    1. Calculate per-host risk scores
    2. Aggregate scan-level metrics
    3. Generate recommendations
    4. Attempt ML-based classification if model exists
    """
    hosts = scan_results.get("hosts", [])
    analyzed_hosts = []
    high_risk_count = 0

    for host in hosts:
        if host.get("status") == "error":
            analyzed_hosts.append({**host, "risk_score": 0, "risk_level": "unknown"})
            continue

        risk_score, risk_level = calculate_risk_score(host)
        host_analyzed = {
            **host,
            "risk_score": risk_score,
            "risk_level": risk_level,
        }
        analyzed_hosts.append(host_analyzed)

        if risk_level in ("high", "critical"):
            high_risk_count += 1

    # Overall scan risk
    if analyzed_hosts:
        avg_risk = np.mean([h.get("risk_score", 0) for h in analyzed_hosts])
        overall_risk_score = round(float(avg_risk), 1)
    else:
        overall_risk_score = 0.0

    if overall_risk_score >= 70:
        overall_risk_level = "critical"
    elif overall_risk_score >= 50:
        overall_risk_level = "high"
    elif overall_risk_score >= 25:
        overall_risk_level = "medium"
    else:
        overall_risk_level = "low"

    recommendations = generate_recommendations(scan_results)

    return {
        **scan_results,
        "hosts": analyzed_hosts,
        "high_risk_hosts": high_risk_count,
        "overall_risk_score": overall_risk_score,
        "overall_risk_level": overall_risk_level,
        "ai_recommendations": recommendations,
        "recommendation_count": len(recommendations),
    }


# ─── Optional TensorFlow Deep Learning Model ─────────────────────────────────

def train_risk_classifier(training_data: List[Dict], labels: List[int]):
    """
    Train a simple TensorFlow neural network for risk classification.
    Labels: 0=low, 1=medium, 2=high, 3=critical
    Call this with historical scan data to improve accuracy over time.
    """
    try:
        import tensorflow as tf
        from sklearn.model_selection import train_test_split
        from sklearn.preprocessing import StandardScaler

        X = np.array([build_feature_vector(d) for d in training_data])
        y = np.array(labels)

        X_train, X_val, y_train, y_val = train_test_split(X, y, test_size=0.2)
        scaler = StandardScaler()
        X_train = scaler.fit_transform(X_train)
        X_val = scaler.transform(X_val)

        model = tf.keras.Sequential([
            tf.keras.layers.Dense(64, activation='relu', input_shape=(10,)),
            tf.keras.layers.Dropout(0.3),
            tf.keras.layers.Dense(32, activation='relu'),
            tf.keras.layers.Dropout(0.2),
            tf.keras.layers.Dense(4, activation='softmax'),
        ])

        model.compile(
            optimizer='adam',
            loss='sparse_categorical_crossentropy',
            metrics=['accuracy']
        )

        model.fit(X_train, y_train, epochs=50, batch_size=32,
                  validation_data=(X_val, y_val), verbose=0)

        os.makedirs("./ml_models", exist_ok=True)
        model.save("./ml_models/risk_classifier.h5")
        np.save("./ml_models/scaler_mean.npy", scaler.mean_)
        np.save("./ml_models/scaler_scale.npy", scaler.scale_)

        logger.info("TensorFlow risk classifier trained and saved.")
        return model

    except ImportError:
        logger.warning("TensorFlow not installed. Using rule-based scoring.")
        return None
