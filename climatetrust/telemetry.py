"""Telemetry ingestion engine and adversarial attack simulator for climate data."""

import math
import random
import time
from typing import List, Dict, Tuple, Optional
from climatetrust.types import TelemetryPoint, AttackType


class ClimateTelemetryGenerator:
    """Generates synthetic, physics-informed environmental telemetry with optional adversarial injections."""

    # Default regional clusters (e.g. Industrial Hub, Urban Center, Baseline Nature Reserve)
    CLUSTERS: Dict[str, Dict[str, float]] = {
        "INDUSTRIAL_ZONE_NORTH": {
            "lat": 40.7128, "lon": -74.0060,
            "base_co2": 520.0, "base_ch4": 2250.0, "base_pm25": 42.0
        },
        "URBAN_METRO_CORE": {
            "lat": 40.7589, "lon": -73.9851,
            "base_co2": 445.0, "base_ch4": 1950.0, "base_pm25": 24.0
        },
        "COASTAL_BASELINE_PARK": {
            "lat": 40.6022, "lon": -74.1502,
            "base_co2": 418.0, "base_ch4": 1820.0, "base_pm25": 9.0
        }
    }

    def __init__(self, seed: Optional[int] = 42):
        self.rng = random.Random(seed)

    def generate_epoch_telemetry(
        self,
        epoch_timestamp: Optional[int] = None,
        samples_per_cluster: int = 5,
        inject_attacks: bool = True
    ) -> List[TelemetryPoint]:
        """Generate a batch of telemetry points across clusters for an epoch.
        
        Args:
            epoch_timestamp: Base unix timestamp for the epoch.
            samples_per_cluster: Number of stations per cluster.
            inject_attacks: If True, randomly injects adversarial attacks on designated stations.
        """
        ts = epoch_timestamp or int(time.time())
        points: List[TelemetryPoint] = []
        station_counter = 1

        # Diurnal solar cycle calculation (24h period)
        hour_of_day = (ts % 86400) / 3600.0
        solar_factor = math.sin((hour_of_day - 6) * math.pi / 12.0)  # Peak at midday

        for cluster_name, spec in self.CLUSTERS.items():
            base_temp = 18.0 + 8.0 * max(-0.5, solar_factor)
            base_humidity = 60.0 - 15.0 * max(-0.5, solar_factor)

            for i in range(samples_per_cluster):
                station_id = f"STN-{cluster_name[:4]}-{station_counter:03d}"
                station_counter += 1

                # Spatial jitter within ~2km
                lat_jitter = self.rng.uniform(-0.015, 0.015)
                lon_jitter = self.rng.uniform(-0.015, 0.015)

                # Atmospheric natural turbulence noise
                co2_noise = self.rng.gauss(0, 4.5)
                ch4_noise = self.rng.gauss(0, 25.0)
                pm25_noise = self.rng.gauss(0, 2.0)
                temp_noise = self.rng.gauss(0, 0.5)
                hum_noise = self.rng.gauss(0, 1.5)

                point = TelemetryPoint(
                    station_id=station_id,
                    timestamp=ts + self.rng.randint(-30, 30),
                    latitude=spec["lat"] + lat_jitter,
                    longitude=spec["lon"] + lon_jitter,
                    co2_ppm=max(350.0, spec["base_co2"] + co2_noise),
                    ch4_ppb=max(1500.0, spec["base_ch4"] + ch4_noise),
                    pm25_ugm3=max(1.0, spec["base_pm25"] + pm25_noise),
                    temperature_c=base_temp + temp_noise,
                    humidity_pct=min(100.0, max(10.0, base_humidity + hum_noise)),
                    source_api="Copernicus-Sentinel5P/OpenAQ-Edge",
                    attack_injected=AttackType.NONE,
                    metadata={"cluster": cluster_name, "is_simulated": True}
                )
                points.append(point)

        if inject_attacks and len(points) >= 4:
            self._inject_adversarial_scenarios(points)

        return points

    def _inject_adversarial_scenarios(self, points: List[TelemetryPoint]) -> None:
        """Inject realistic adversarial cyber attacks and telemetry falsification."""
        # 1. Under-reporting attack: Industrial facility intentionally reports baseline numbers despite high emission
        target_idx_1 = 0
        points[target_idx_1].attack_injected = AttackType.UNDER_REPORTING
        points[target_idx_1].metadata["ground_truth_co2"] = points[target_idx_1].co2_ppm
        # Artificially clamp CO2 from e.g. 520 to pristine 412 ppm
        points[target_idx_1].co2_ppm = 412.5 + self.rng.uniform(-0.5, 0.5)
        points[target_idx_1].metadata["tamper_reason"] = "Tax-evasion under-reporting clamp"

        # 2. Synthetic Flatline: Spoofed / dead sensor replaying identical mock data without atmospheric entropy
        if len(points) > 1:
            target_idx_2 = 1
            points[target_idx_2].attack_injected = AttackType.SYNTHETIC_FLATLINE
            points[target_idx_2].co2_ppm = 420.000000
            points[target_idx_2].ch4_ppb = 1900.000000
            points[target_idx_2].pm25_ugm3 = 15.000000
            points[target_idx_2].temperature_c = 22.000000
            points[target_idx_2].humidity_pct = 50.000000
            points[target_idx_2].metadata["tamper_reason"] = "Synthetic zero-variance mock payload"

        # 3. Sensor Spoofing: Forest station claiming coastal clean coords but emitting industrial smoke fingerprint
        if len(points) > 2:
            target_idx_3 = len(points) - 1
            points[target_idx_3].attack_injected = AttackType.SENSOR_SPOOFING
            points[target_idx_3].co2_ppm = 610.5  # Extreme industrial spike inside coastal pristine park
            points[target_idx_3].ch4_ppb = 3100.0
            points[target_idx_3].pm25_ugm3 = 85.0
            points[target_idx_3].metadata["tamper_reason"] = "Location coordinate spoofing / forged identity"
