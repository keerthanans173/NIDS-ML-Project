"""
SentinelFlow Network Traffic Simulator & Replay Streamer
Provides:
1. Live network replay streaming from KDDTest+ at 1x/5x/10x speeds via Socket.IO
2. Synthetic attack traffic injection (DoS, Probe, R2L, U2R) with intensity controls
"""

import os
import time
import random
import threading
import logging
import pandas as pd

from app.ml.preprocess import (
    ALL_FEATURES, PRESETS, DEFAULT_FEATURE_VALUES, map_raw_label
)

logger = logging.getLogger("sentinel.services.simulator")

BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
TEST_DATA_PATH = os.path.join(BASE_DIR, "data", "KDDTest+.txt")

class TrafficSimulator:
    _instance = None

    def __init__(self, socketio=None):
        self.socketio = socketio
        self.is_streaming = False
        self.stream_speed = 1.0  # 1x, 5x, 10x
        self._thread = None
        self._stop_event = threading.Event()
        self.test_data_cache = None

    @classmethod
    def get_instance(cls, socketio=None):
        if cls._instance is None:
            cls._instance = TrafficSimulator(socketio=socketio)
        elif socketio is not None and cls._instance.socketio is None:
            cls._instance.socketio = socketio
        return cls._instance

    def _load_sample_data(self):
        """Loads cached sample from KDDTest+."""
        if self.test_data_cache is None and os.path.exists(TEST_DATA_PATH):
            try:
                # Load up to 5000 test rows
                cols = ALL_FEATURES + ["label", "difficulty"]
                df = pd.read_csv(TEST_DATA_PATH, header=None, names=cols, nrows=5000, low_memory=False)
                df = df[df["duration"] != "duration"].reset_index(drop=True)
                df.drop("difficulty", axis=1, inplace=True, errors="ignore")
                df["label"] = df["label"].apply(map_raw_label)
                self.test_data_cache = df
                logger.info(f"Loaded {len(df)} sample packets for live replay.")
            except Exception as e:
                logger.error(f"Failed to load replay test data: {e}")
                self.test_data_cache = pd.DataFrame()

    def start_replay(self, speed: float = 1.0, app=None):
        """Starts live stream replay in background thread."""
        if self.is_streaming:
            self.stream_speed = max(0.5, min(10.0, float(speed)))
            return True

        self._load_sample_data()
        if self.test_data_cache is None or self.test_data_cache.empty:
            return False

        self.stream_speed = max(0.5, min(10.0, float(speed)))
        self.is_streaming = True
        self._stop_event.clear()

        self._thread = threading.Thread(
            target=self._stream_loop,
            args=(app,),
            daemon=True,
            name="SentinelReplayWorker"
        )
        self._thread.start()
        logger.info(f"Traffic replay started at {self.stream_speed}x speed.")
        return True

    def stop_replay(self):
        """Stops live replay stream."""
        self.is_streaming = False
        self._stop_event.set()
        logger.info("Traffic replay stopped.")

    def set_speed(self, speed: float):
        self.stream_speed = max(0.5, min(10.0, float(speed)))
        logger.info(f"Replay stream speed set to {self.stream_speed}x.")

    def _stream_loop(self, app):
        """Internal background loop that reads rows and emits packet telemetry."""
        from app.services.detector import SentinelDetector
        from app.models import db, Prediction, Alert
        detector = SentinelDetector.get_instance()

        row_idx = 0
        total_rows = len(self.test_data_cache)

        # Base interval is 1.0s / stream_speed
        while not self._stop_event.is_set() and self.is_streaming:
            row = self.test_data_cache.iloc[row_idx % total_rows].to_dict()
            row_idx += 1

            # Prepare features
            packet_data = {f: row.get(f, DEFAULT_FEATURE_VALUES.get(f, 0)) for f in ALL_FEATURES}
            ground_truth = row.get("label", "Normal")

            # Run detection
            result = detector.predict_one(packet_data)

            # Persist and broadcast within application context
            if app:
                try:
                    with app.app_context():
                        pred = Prediction(
                            attack_type=result["attack_type"],
                            confidence=result["confidence"],
                            risk_score=result["risk_score"],
                            threat_level=result["threat_level"],
                            traffic_status=result["traffic_status"],
                            protocol_type=str(packet_data.get("protocol_type", "tcp")),
                            service=str(packet_data.get("service", "http")),
                            flag=str(packet_data.get("flag", "SF")),
                            src_bytes=float(packet_data.get("src_bytes", 0)),
                            dst_bytes=float(packet_data.get("dst_bytes", 0)),
                            count=int(packet_data.get("count", 1)),
                            serror_rate=float(packet_data.get("serror_rate", 0)),
                            source_ip=result["source_ip"],
                            is_flagged=(result["attack_type"] != "Normal")
                        )
                        db.session.add(pred)
                        db.session.flush()

                        alert_payload = None
                        if result["attack_type"] != "Normal":
                            alert = Alert(
                                prediction_id=pred.id,
                                attack_type=result["attack_type"],
                                severity=result["threat_level"],
                                risk_score=result["risk_score"],
                                confidence=result["confidence"],
                                source_ip=result["source_ip"],
                                status="New",
                                summary=f"{result['threat_level']} severity {result['attack_type']} attack detected",
                                explanation=result["explanation"],
                                top_features_json=str(result["top_features"])
                            )
                            db.session.add(alert)
                            db.session.flush()
                            alert_payload = alert.to_dict()

                        db.session.commit()

                        # Broadcast via SocketIO
                        if self.socketio:
                            packet_payload = {
                                "id": pred.id,
                                "attack_type": result["attack_type"],
                                "confidence": result["confidence"],
                                "risk_score": result["risk_score"],
                                "threat_level": result["threat_level"],
                                "traffic_status": result["traffic_status"],
                                "source_ip": result["source_ip"],
                                "protocol": packet_data.get("protocol_type"),
                                "service": packet_data.get("service"),
                                "flag": packet_data.get("flag"),
                                "ground_truth": ground_truth,
                                "timestamp": time.strftime("%H:%M:%S"),
                                "explanation": result["explanation"],
                                "is_simulated": True
                            }
                            self.socketio.emit("traffic_packet", packet_payload)
                            if alert_payload:
                                self.socketio.emit("new_alert", alert_payload)

                except Exception as ex:
                    logger.error(f"Error in stream loop DB persistence: {ex}")

            # Sleep between packets
            sleep_duration = max(0.1, 1.2 / self.stream_speed)
            time.sleep(sleep_duration)

    def inject_synthetic_attack(self, attack_type: str, intensity: int = 5, app=None) -> list:
        """
        Injects a burst of synthetic packets for a specified attack type.
        Adds realistic jitter/variance to demonstrate detection & alert trigger.
        """
        from app.services.detector import SentinelDetector
        from app.models import db, Prediction, Alert
        detector = SentinelDetector.get_instance()

        template = PRESETS.get(attack_type, PRESETS["DoS"])
        results = []

        intensity = max(1, min(50, int(intensity)))
        for i in range(intensity):
            sample = template.copy()
            # Inject realistic telemetry jitter
            if attack_type == "DoS":
                sample["count"] = max(100, template["count"] + random.randint(-40, 80))
                sample["serror_rate"] = min(1.0, max(0.7, template["serror_rate"] + random.uniform(-0.15, 0.0)))
                sample["dst_host_count"] = random.randint(200, 255)
            elif attack_type == "Probe":
                sample["rerror_rate"] = min(1.0, max(0.6, template["rerror_rate"] + random.uniform(-0.2, 0.0)))
                sample["diff_srv_rate"] = min(1.0, max(0.05, template["diff_srv_rate"] + random.uniform(-0.02, 0.05)))
            elif attack_type == "R2L":
                sample["num_failed_logins"] = random.randint(2, 8)
                sample["src_bytes"] = max(200, template["src_bytes"] + random.randint(-200, 500))
            elif attack_type == "U2R":
                sample["num_root"] = random.randint(1, 6)
                sample["root_shell"] = random.choice([0, 1])

            res = detector.predict_one(sample)
            results.append(res)

            # Persist in DB and broadcast
            if app:
                try:
                    with app.app_context():
                        pred = Prediction(
                            attack_type=res["attack_type"],
                            confidence=res["confidence"],
                            risk_score=res["risk_score"],
                            threat_level=res["threat_level"],
                            traffic_status=res["traffic_status"],
                            protocol_type=str(sample.get("protocol_type", "tcp")),
                            service=str(sample.get("service", "http")),
                            flag=str(sample.get("flag", "SF")),
                            src_bytes=float(sample.get("src_bytes", 0)),
                            dst_bytes=float(sample.get("dst_bytes", 0)),
                            count=int(sample.get("count", 1)),
                            serror_rate=float(sample.get("serror_rate", 0)),
                            source_ip=res["source_ip"],
                            is_flagged=(res["attack_type"] != "Normal")
                        )
                        db.session.add(pred)
                        db.session.flush()

                        alert_obj = None
                        if res["attack_type"] != "Normal":
                            alert_obj = Alert(
                                prediction_id=pred.id,
                                attack_type=res["attack_type"],
                                severity=res["threat_level"],
                                risk_score=res["risk_score"],
                                confidence=res["confidence"],
                                source_ip=res["source_ip"],
                                status="New",
                                summary=f"Synthetic {res['attack_type']} attack burst injected",
                                explanation=res["explanation"],
                                top_features_json=str(res["top_features"])
                            )
                            db.session.add(alert_obj)
                            db.session.flush()

                        db.session.commit()

                        if self.socketio:
                            packet_payload = {
                                "id": pred.id,
                                "attack_type": res["attack_type"],
                                "confidence": res["confidence"],
                                "risk_score": res["risk_score"],
                                "threat_level": res["threat_level"],
                                "traffic_status": res["traffic_status"],
                                "source_ip": res["source_ip"],
                                "protocol": sample.get("protocol_type"),
                                "service": sample.get("service"),
                                "flag": sample.get("flag"),
                                "timestamp": time.strftime("%H:%M:%S"),
                                "explanation": res["explanation"],
                                "is_simulated": True
                            }
                            self.socketio.emit("traffic_packet", packet_payload)
                            if alert_obj:
                                self.socketio.emit("new_alert", alert_obj.to_dict())

                except Exception as e:
                    logger.error(f"Error persisting synthetic attack: {e}")

        return results
