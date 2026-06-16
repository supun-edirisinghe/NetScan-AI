"""
ml_trainer.py
─────────────
Standalone script to train and save ML models for risk classification.
Run this once after collecting enough scan data, or use synthetic data to bootstrap.

Usage:
    python ml_trainer.py                  # train with synthetic data
    python ml_trainer.py --use-db         # train from PostgreSQL scan history
"""
import numpy as np
import os
import json
import argparse
import logging
from pathlib import Path

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("ml_trainer")

MODEL_DIR = Path("./ml_models")
MODEL_DIR.mkdir(exist_ok=True)


# ── Feature engineering (mirrors ai_analyzer.py) ─────────────────────────────

def host_to_features(host_data: dict) -> np.ndarray:
    open_ports = host_data.get("open_ports", [])
    port_numbers = [p["port"] for p in open_ports]

    high_risk  = {23, 21, 445, 3389, 4444, 6379, 27017, 9200}
    medium_risk = {135, 139, 5900, 1433, 1521, 3306}

    return np.array([
        len(open_ports),
        len([p for p in port_numbers if p in high_risk]),
        len([p for p in port_numbers if p in medium_risk]),
        sum(p.get("risk_weight", 0.2) for p in open_ports),
        1 if 80  in port_numbers or 8080 in port_numbers else 0,
        1 if 443 in port_numbers or 8443 in port_numbers else 0,
        1 if 22  in port_numbers else 0,
        1 if any(p in port_numbers for p in [3306, 5432, 1433, 27017]) else 0,
        max((p.get("risk_weight", 0) for p in open_ports), default=0),
        len(set(port_numbers)) / max(len(port_numbers), 1),
    ], dtype=np.float32)


def label_from_host(host_data: dict) -> int:
    """Derive ground-truth label from risk_weight heuristic. 0=low,1=med,2=high,3=critical"""
    open_ports = host_data.get("open_ports", [])
    port_numbers = [p["port"] for p in open_ports]
    critical_ports = {23, 445, 4444, 6379, 27017}
    if any(p in port_numbers for p in critical_ports):
        return 3
    high_ports = {21, 3389, 9200, 5900}
    if any(p in port_numbers for p in high_ports):
        return 2
    if len(open_ports) > 10:
        return 1
    return 0


# ── Synthetic data generator ──────────────────────────────────────────────────

def generate_synthetic_data(n=2000):
    from app.services.scanner import PORT_RISK_WEIGHTS, KNOWN_SERVICES

    all_ports = list(PORT_RISK_WEIGHTS.keys()) + list(range(1, 1025, 50))
    X, y = [], []

    np.random.seed(42)
    for _ in range(n):
        n_ports = np.random.choice([0, 1, 2, 5, 10, 20], p=[0.15, 0.2, 0.2, 0.2, 0.15, 0.1])
        chosen = np.random.choice(all_ports, size=min(n_ports, len(all_ports)), replace=False)
        host = {
            "open_ports": [
                {"port": p, "service": KNOWN_SERVICES.get(p, "unknown"),
                 "risk_weight": PORT_RISK_WEIGHTS.get(p, 0.2)}
                for p in chosen
            ]
        }
        X.append(host_to_features(host))
        y.append(label_from_host(host))

    return np.array(X), np.array(y)


# ── Scikit-learn Random Forest ────────────────────────────────────────────────

def train_sklearn(X_train, y_train, X_val, y_val):
    from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
    from sklearn.preprocessing import StandardScaler
    from sklearn.metrics import classification_report
    import joblib

    scaler = StandardScaler()
    Xs_train = scaler.fit_transform(X_train)
    Xs_val   = scaler.transform(X_val)

    rf = RandomForestClassifier(n_estimators=200, max_depth=10, random_state=42, n_jobs=-1)
    rf.fit(Xs_train, y_train)

    y_pred = rf.predict(Xs_val)
    logger.info("Random Forest Report:\n" + classification_report(
        y_val, y_pred, target_names=["low", "medium", "high", "critical"]
    ))

    joblib.dump(rf, MODEL_DIR / "rf_risk_classifier.joblib")
    joblib.dump(scaler, MODEL_DIR / "rf_scaler.joblib")
    logger.info("Saved: rf_risk_classifier.joblib + rf_scaler.joblib")
    return rf, scaler


# ── TensorFlow Neural Network ─────────────────────────────────────────────────

def train_tensorflow(X_train, y_train, X_val, y_val):
    try:
        import tensorflow as tf
        from sklearn.preprocessing import StandardScaler

        scaler = StandardScaler()
        Xs_train = scaler.fit_transform(X_train)
        Xs_val   = scaler.transform(X_val)

        model = tf.keras.Sequential([
            tf.keras.layers.Input(shape=(10,)),
            tf.keras.layers.Dense(128, activation="relu"),
            tf.keras.layers.BatchNormalization(),
            tf.keras.layers.Dropout(0.3),
            tf.keras.layers.Dense(64, activation="relu"),
            tf.keras.layers.Dropout(0.2),
            tf.keras.layers.Dense(32, activation="relu"),
            tf.keras.layers.Dense(4, activation="softmax"),
        ])

        model.compile(
            optimizer=tf.keras.optimizers.Adam(0.001),
            loss="sparse_categorical_crossentropy",
            metrics=["accuracy"],
        )

        callbacks = [
            tf.keras.callbacks.EarlyStopping(patience=10, restore_best_weights=True),
            tf.keras.callbacks.ReduceLROnPlateau(patience=5, factor=0.5),
        ]

        history = model.fit(
            Xs_train, y_train,
            epochs=100, batch_size=64,
            validation_data=(Xs_val, y_val),
            callbacks=callbacks, verbose=1,
        )

        loss, acc = model.evaluate(Xs_val, y_val, verbose=0)
        logger.info(f"TensorFlow model — val_accuracy: {acc:.4f}")

        model.save(MODEL_DIR / "tf_risk_classifier.keras")
        np.save(MODEL_DIR / "tf_scaler_mean.npy",  scaler.mean_)
        np.save(MODEL_DIR / "tf_scaler_scale.npy", scaler.scale_)
        logger.info("Saved: tf_risk_classifier.keras")
        return model

    except ImportError:
        logger.warning("TensorFlow not installed — skipping TF model.")
        return None


# ── Load from DB ──────────────────────────────────────────────────────────────

def load_from_db():
    """Pull completed scan host data from PostgreSQL to build training set."""
    import asyncio
    from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
    from sqlalchemy import select
    from app.core.config import settings
    from app.models.scan import Scan, ScanStatus

    async def _fetch():
        engine = create_async_engine(settings.DATABASE_URL)
        session_factory = async_sessionmaker(engine, class_=AsyncSession)
        X, y = [], []
        async with session_factory() as session:
            result = await session.execute(
                select(Scan).where(Scan.status == ScanStatus.COMPLETED)
            )
            scans = result.scalars().all()
            logger.info(f"Loading {len(scans)} completed scans from DB...")
            for scan in scans:
                hosts = (scan.scan_results or {}).get("hosts", [])
                for host in hosts:
                    X.append(host_to_features(host))
                    y.append(label_from_host(host))
        await engine.dispose()
        return np.array(X), np.array(y)

    return asyncio.run(_fetch())


# ── Main ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--use-db", action="store_true", help="Load training data from PostgreSQL")
    parser.add_argument("--no-tf", action="store_true", help="Skip TensorFlow model")
    args = parser.parse_args()

    from sklearn.model_selection import train_test_split

    if args.use_db:
        X, y = load_from_db()
        logger.info(f"Loaded {len(X)} samples from DB")
    else:
        logger.info("Generating synthetic training data...")
        X, y = generate_synthetic_data(n=3000)

    logger.info(f"Dataset: {len(X)} samples | Class distribution: {np.bincount(y)}")

    X_train, X_val, y_train, y_val = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

    logger.info("Training Scikit-learn Random Forest...")
    train_sklearn(X_train, y_train, X_val, y_val)

    if not args.no_tf:
        logger.info("Training TensorFlow Neural Network...")
        train_tensorflow(X_train, y_train, X_val, y_val)

    logger.info(f"All models saved to {MODEL_DIR.resolve()}")
