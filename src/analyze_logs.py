
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


def analyze_logs() -> pd.DataFrame:
    """Detect repeated authentication failures and subsequent successes."""
    df = pd.read_csv(INPUT_FILE)

    missing_columns = REQUIRED_COLUMNS - set(df.columns)
    if missing_columns:
        raise ValueError(f"Missing required columns: {sorted(missing_columns)}")

    df["timestamp"] = pd.to_datetime(df["timestamp"], utc=True, errors="coerce")
    df["event_type"] = df["event_type"].astype(str).str.strip().str.lower()
    df["username"] = df["username"].astype(str).str.strip()
    df["source_ip"] = df["source_ip"].astype(str).str.strip()

    df = df.dropna(subset=["timestamp"]).sort_values("timestamp").reset_index(drop=True)

    alerts = []

    # Check each username and source IP combination.
    for (username, source_ip), group in df.groupby(["username", "source_ip"]):
        group = group.sort_values("timestamp").reset_index(drop=True)
        failures = group[group["event_type"] == "failure"]

        for _, failure in failures.iterrows():
            window_start = failure["timestamp"] - pd.Timedelta(minutes=5)

            recent_failures = failures[
                (failures["timestamp"] >= window_start)
                & (failures["timestamp"] <= failure["timestamp"])
            ]

            if len(recent_failures) == 5:
                # Alert only once, when the fifth failure is reached.
                alerts.append({
                    "timestamp": failure["timestamp"].isoformat(),
                    "username": username,
                    "source_ip": source_ip,
                    "alert_type": "Repeated Authentication Failures",
                    "failure_count": len(recent_failures),
                    "details": "Five failed logins within five minutes.",
                })

                # Look for a success in the five minutes after the fifth failure.
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
                            "Successful login followed five failed logins. "
                            f"Resource: {success['resource']}"
                        ),
                    })

    columns = [
        "timestamp",
        "username",
        "source_ip",
        "alert_type",
        "failure_count",
        "details",
    ]
    return pd.DataFrame(alerts, columns=columns)


if __name__ == "__main__":
    results = analyze_logs()
    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    results.to_csv(OUTPUT_FILE, index=False)

    print(f"Analysis complete. Alerts found: {len(results)}")
    print(f"Report saved to: {OUTPUT_FILE}")
    if not results.empty:
        print(results.to_string(index=False))
