
from pathlib import Path

import pandas as pd


PROJECT_ROOT = Path(__file__).resolve().parent.parent
INPUT_FILE = PROJECT_ROOT / "data" / "auth_events.csv"
OUTPUT_FILE = PROJECT_ROOT / "reports" / "suspicious_events.csv"

REQUIRED_COLUMNS = {
    "timestamp",
    "username",
    "source_ip",
    "event_type",
    "resource",
}

ALERT_COLUMNS = [
    "timestamp",
    "username",
    "source_ip",
    "alert_type",
    "failure_count",
    "details",
]


def analyze_dataframe(df: pd.DataFrame) -> pd.DataFrame:
    """Detect repeated authentication failures and subsequent successes."""
    missing_columns = REQUIRED_COLUMNS - set(df.columns)
    if missing_columns:
        raise ValueError(f"Missing required columns: {sorted(missing_columns)}")

    df = df.copy()
    df["timestamp"] = pd.to_datetime(
        df["timestamp"], utc=True, errors="coerce"
    )
    df["event_type"] = df["event_type"].astype(str).str.strip().str.lower()
    df["username"] = df["username"].astype(str).str.strip()
    df["source_ip"] = df["source_ip"].astype(str).str.strip()

    df = (
        df.dropna(subset=["timestamp"])
        .sort_values("timestamp")
        .reset_index(drop=True)
    )

    alerts = []

    for (username, source_ip), group in df.groupby(["username", "source_ip"]):
        group = group.sort_values("timestamp").reset_index(drop=True)
        failures = group[group["event_type"] == "failure"]

        alerted_for_cluster = False

        for _, failure in failures.iterrows():
            window_start = failure["timestamp"] - pd.Timedelta(minutes=5)

            recent_failures = failures[
                (failures["timestamp"] >= window_start)
                & (failures["timestamp"] <= failure["timestamp"])
            ]

            if len(recent_failures) >= 5 and not alerted_for_cluster:
                alerted_for_cluster = True

                alerts.append({
                    "timestamp": failure["timestamp"].isoformat(),
                    "username": username,
                    "source_ip": source_ip,
                    "alert_type": "Repeated Authentication Failures",
                    "failure_count": len(recent_failures),
                    "details": (
                        f"{len(recent_failures)} failed logins "
                        "within five minutes."
                    ),
                })

                later_successes = group[
                    (group["event_type"] == "success")
                    & (group["timestamp"] > failure["timestamp"])
                    & (
                        group["timestamp"]
                        <= failure["timestamp"] + pd.Timedelta(minutes=5)
                    )
                ]

                if not later_successes.empty:
                    success = later_successes.iloc[0]

                    alerts.append({
                        "timestamp": success["timestamp"].isoformat(),
                        "username": username,
                        "source_ip": source_ip,
                        "alert_type": "Success After Repeated Failures",
                        "failure_count": len(recent_failures),
                        "details": (
                            "Successful login followed repeated failures. "
                            f"Resource: {success['resource']}"
                        ),
                    })

    return pd.DataFrame(alerts, columns=ALERT_COLUMNS)


def analyze_logs() -> pd.DataFrame:
    """Load the configured CSV file and analyze its events."""
    df = pd.read_csv(INPUT_FILE)
    return analyze_dataframe(df)


if __name__ == "__main__":
    results = analyze_logs()
    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    results.to_csv(OUTPUT_FILE, index=False)

    print(f"Analysis complete. Alerts found: {len(results)}")
    print(f"Report saved to: {OUTPUT_FILE}")

    if not results.empty:
        print(results.to_string(index=False))
