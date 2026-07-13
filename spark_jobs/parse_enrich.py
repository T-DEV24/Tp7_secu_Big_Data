"""
spark_jobs/parse_enrich.py
Enrichissement typé des logs d'accès.

Les fonctions contrôlent explicitement les timestamps, booléens et nombres avant
le scoring afin d'éviter toute comparaison de chaînes sur des données critiques.
"""
from typing import Any

import pandas as pd


def build_spark_session(app_name: str = "AccessSecuritySOC"):
    """Crée une session Spark pour le pipeline TP7."""
    from pyspark.sql import SparkSession
    return SparkSession.builder.appName(app_name).getOrCreate()


def enrich_events(spark: Any, logs_path: str = "datasets/access_logs.csv", users_path: str = "datasets/users.csv", resources_path: str = "datasets/resources.csv"):
    """Charge, joint et type les événements avec Spark."""
    from pyspark.sql.functions import col, hour, to_timestamp
    from pyspark.sql.types import BooleanType, IntegerType

    logs = spark.read.csv(logs_path, header=True, inferSchema=True)
    users = spark.read.csv(users_path, header=True, inferSchema=True)
    resources = spark.read.csv(resources_path, header=True, inferSchema=True)

    user_cols = ["user_id"] + [name for name in ("role", "department") if name not in logs.columns]
    resource_cols = ["resource_id"] + [name for name in ("sensitivity", "owner_department") if name not in logs.columns]
    if len(user_cols) > 1:
        logs = logs.join(users.select(*user_cols), on="user_id", how="left")
    if len(resource_cols) > 1:
        logs = logs.join(resources.select(*resource_cols), on="resource_id", how="left")

    return (logs
            .withColumn("timestamp", to_timestamp(col("timestamp")))
            .withColumn("success", col("success").cast(BooleanType()))
            .withColumn("mfa_passed", col("mfa_passed").cast(BooleanType()))
            .withColumn("bytes", col("bytes").cast(IntegerType()))
            .withColumn("hour", hour(col("timestamp"))))


def enrich_events_pandas(logs_path: str = "datasets/access_logs.csv", users_path: str = "datasets/users.csv", resources_path: str = "datasets/resources.csv") -> pd.DataFrame:
    """Version pandas de secours, identique fonctionnellement à enrich_events."""
    logs = pd.read_csv(logs_path)
    users = pd.read_csv(users_path)
    resources = pd.read_csv(resources_path)

    user_cols = ["user_id"] + [name for name in ("role", "department") if name not in logs.columns]
    resource_cols = ["resource_id"] + [name for name in ("sensitivity", "owner_department") if name not in logs.columns]
    if len(user_cols) > 1:
        logs = logs.merge(users[user_cols], on="user_id", how="left")
    if len(resource_cols) > 1:
        logs = logs.merge(resources[resource_cols], on="resource_id", how="left")

    logs["timestamp"] = pd.to_datetime(logs["timestamp"], errors="coerce")
    logs["success"] = logs["success"].astype(str).str.lower().isin(["true", "1", "yes", "oui"])
    logs["mfa_passed"] = logs["mfa_passed"].astype(str).str.lower().isin(["true", "1", "yes", "oui"])
    logs["bytes"] = pd.to_numeric(logs["bytes"], errors="coerce").fillna(0).astype(int)
    logs["hour"] = logs["timestamp"].dt.hour
    return logs
