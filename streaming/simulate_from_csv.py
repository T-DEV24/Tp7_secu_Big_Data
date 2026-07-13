"""
streaming/simulate_from_csv.py
Simulateur CSV du flux access_logs.

Ce simulateur remplace Kafka sur un poste sans broker disponible, tout en
conservant exactement le même contrat de données que le producteur réel : ordre
stable des champs, booléens typés et volume bytes numérique.
"""
import csv
import time
from collections import OrderedDict
from typing import Generator


def _cast_bool(value) -> bool:
    """Convertit explicitement une valeur CSV en booléen Python."""
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"true", "1", "yes", "oui"}


def stream_events(csv_path: str = "datasets/access_logs.csv", delay_seconds: float = 0.05) -> Generator[dict, None, None]:
    """
    Émet les événements access_logs ligne par ligne avec un contrat JSON stable.

    Les clés restent strictement celles du CSV et dans le même ordre logique pour
    tous les événements. Les champs success/mfa_passed sont convertis en bool et
    bytes en int avant le yield.
    """
    with open(csv_path, newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        fieldnames = reader.fieldnames or []
        for row in reader:
            event = OrderedDict()
            for field in fieldnames:
                value = row.get(field, "")
                if field in {"success", "mfa_passed"}:
                    value = _cast_bool(value)
                elif field == "bytes":
                    value = int(value or 0)
                event[field] = value
            if delay_seconds > 0:
                time.sleep(delay_seconds)
            yield dict(event)
