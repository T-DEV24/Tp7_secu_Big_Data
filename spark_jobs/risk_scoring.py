"""
spark_jobs/risk_scoring.py
Scoring de risque TP7 avec justifications explicites.
"""
from collections import defaultdict
from datetime import datetime

INTERNAL_IP_PREFIXES = ("10.", "192.168.", "172.16.")
ALERT_SCORE_THRESHOLD = 6


def _as_bool(value) -> bool:
    """Normalise les booléens issus de CSV, pandas ou MongoDB."""
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"true", "1", "yes", "oui"}


def _event_hour(event: dict) -> int | None:
    """Retourne l'heure typée depuis hour ou timestamp.

    Une colonne 'hour' issue d'un DataFrame pandas partiellement vide peut
    contenir un float NaN plutôt que None : NaN n'est pas None, mais
    int(NaN) lève une ValueError. On le détecte explicitement (NaN != NaN)
    et on retombe sur le timestamp dans ce cas.
    """
    hour_val = event.get("hour")
    is_nan = isinstance(hour_val, float) and hour_val != hour_val
    if hour_val is not None and not is_nan:
        try:
            return int(hour_val)
        except (TypeError, ValueError):
            pass
    timestamp = event.get("timestamp")
    if isinstance(timestamp, datetime):
        return timestamp.hour
    try:
        return datetime.fromisoformat(str(timestamp).replace("Z", "+00:00")).hour
    except Exception:
        return None


def _is_external_ip(ip: str) -> bool:
    """Détecte une IP hors plages internes connues."""
    return not str(ip or "").startswith(INTERNAL_IP_PREFIXES)


def score_event(event: dict) -> dict:
    """Ajoute risk_score, risk_level et risk_reasons à un événement enrichi."""
    scored = dict(event)
    score = 0
    reasons = []

    # Authentification échouée → tentative refusée à conserver dans la supervision.
    if not _as_bool(scored.get("success")):
        score += 2
        reasons.append("echec_authentification (+2)")
    # Accès hors heures ouvrées → contexte inhabituel pour un SI hospitalier.
    hour = _event_hour(scored)
    if hour is not None and (hour < 6 or hour > 20):
        score += 2
        reasons.append("hors_heures_ouvrees (+2)")
    # Export de données → risque d'exfiltration.
    if str(scored.get("action", "")).lower() == "export":
        score += 3
        reasons.append("export_donnees (+3)")
    # IP externe ou rare → origine hors réseau interne connu.
    if _is_external_ip(scored.get("ip", "")):
        score += 3
        reasons.append("ip_externe (+3)")
    # MFA non validé → preuve d'identité insuffisante.
    if not _as_bool(scored.get("mfa_passed")):
        score += 2
        reasons.append("mfa_non_valide (+2)")
    # Ressource sensible → impact fort si accès abusif.
    if str(scored.get("sensitivity", "")).lower() in {"sensible", "confidentiel"}:
        score += 2
        reasons.append("ressource_sensible (+2)")

    scored["risk_score"] = int(score)
    scored["risk_level"] = "élevé" if score >= ALERT_SCORE_THRESHOLD else "moyen" if score >= 3 else "faible"
    scored["risk_reasons"] = reasons
    return scored


def score_dataframe(df):
    """Score un DataFrame Spark en conservant les raisons sous forme de tableau."""
    from pyspark.sql.functions import array, array_remove, col, hour, lit, to_timestamp, when

    typed = df.withColumn("_hour", when(col("hour").isNotNull(), col("hour")).otherwise(hour(to_timestamp(col("timestamp")))))
    failed = when(col("success") == False, lit(2)).otherwise(lit(0))
    off_hours = when((col("_hour") < 6) | (col("_hour") > 20), lit(2)).otherwise(lit(0))
    export = when(col("action") == "export", lit(3)).otherwise(lit(0))
    external = when(~(col("ip").startswith("10.") | col("ip").startswith("192.168.") | col("ip").startswith("172.16.")), lit(3)).otherwise(lit(0))
    mfa = when(col("mfa_passed") == False, lit(2)).otherwise(lit(0))
    sensitive = when(col("sensitivity").isin("sensible", "confidentiel"), lit(2)).otherwise(lit(0))
    scored = typed.withColumn("risk_score", failed + off_hours + export + external + mfa + sensitive)
    reasons = array(
        when(failed > 0, lit("echec_authentification (+2)")),
        when(off_hours > 0, lit("hors_heures_ouvrees (+2)")),
        when(export > 0, lit("export_donnees (+3)")),
        when(external > 0, lit("ip_externe (+3)")),
        when(mfa > 0, lit("mfa_non_valide (+2)")),
        when(sensitive > 0, lit("ressource_sensible (+2)")),
    )
    return scored.withColumn("risk_level", when(col("risk_score") >= ALERT_SCORE_THRESHOLD, lit("élevé")).when(col("risk_score") >= 3, lit("moyen")).otherwise(lit("faible"))).withColumn("risk_reasons", array_remove(reasons, None)).drop("_hour")


def score_dataframe_pandas(df):
    """Score un DataFrame pandas via score_event."""
    import pandas as pd
    return pd.DataFrame([score_event(row.to_dict()) for _, row in df.iterrows()])


def top_risky_users(scored_events, n: int = 10) -> list[dict]:
    """Retourne les utilisateurs au score cumulé le plus élevé."""
    records = scored_events.to_dict(orient="records") if hasattr(scored_events, "to_dict") else list(scored_events)
    users = defaultdict(lambda: {"total_score": 0, "nb_alertes": 0, "dernieres_raisons": []})
    for event in records:
        uid = event.get("user_id", "?")
        users[uid]["total_score"] += int(event.get("risk_score", 0) or 0)
        if int(event.get("risk_score", 0) or 0) >= ALERT_SCORE_THRESHOLD:
            users[uid]["nb_alertes"] += 1
            users[uid]["dernieres_raisons"] = list(event.get("risk_reasons") or [])[-3:]
    result = [{"user_id": uid, **values} for uid, values in users.items()]
    return sorted(result, key=lambda item: (item["total_score"], item["nb_alertes"]), reverse=True)[:n]
