
import pandas as pd
import pytest

from src.analyze_logs import analyze_dataframe, analyze_logs


def make_events(event_types, start="2026-10-01T09:00:00Z"):
    """Build a small synthetic dataset with 20-second intervals."""
    start_time = pd.Timestamp(start)
    rows = []

    for i, event_type in enumerate(event_types):
        rows.append({
            "timestamp": (start_time + pd.Timedelta(seconds=20 * i)).isoformat(),
            "username": "testuser",
            "source_ip": "192.0.2.50",
            "event_type": event_type,
            "resource": "email",
        })

    return pd.DataFrame(rows)


def test_sample_dataset_generates_two_alerts():
    alerts = analyze_logs()

    assert len(alerts) == 2
    assert set(alerts["alert_type"]) == {
        "Repeated Authentication Failures",
        "Success After Repeated Failures",
    }


def test_repeated_failures_alert_identifies_alex():
    alerts = analyze_logs()

    repeated = alerts[
        alerts["alert_type"] == "Repeated Authentication Failures"
    ]

    assert len(repeated) == 1
    assert repeated.iloc[0]["username"] == "alex"
    assert repeated.iloc[0]["source_ip"] == "192.0.2.20"
    assert repeated.iloc[0]["failure_count"] == 5


def test_success_alert_mentions_resource():
    alerts = analyze_logs()

    successes = alerts[
        alerts["alert_type"] == "Success After Repeated Failures"
    ]

    assert len(successes) == 1
    assert "Resource: email" in successes.iloc[0]["details"]


def test_normal_successful_activity_generates_no_alerts():
    events = make_events(["success", "success", "success"])

    alerts = analyze_dataframe(events)

    assert alerts.empty


def test_four_failures_do_not_trigger_threshold():
    events = make_events(["failure", "failure", "failure", "failure"])

    alerts = analyze_dataframe(events)

    assert alerts.empty


def test_five_failures_trigger_repeated_failure_alert():
    events = make_events(["failure"] * 5)

    alerts = analyze_dataframe(events)

    repeated = alerts[
        alerts["alert_type"] == "Repeated Authentication Failures"
    ]

    assert len(repeated) == 1
    assert repeated.iloc[0]["failure_count"] == 5


def test_missing_required_column_raises_error():
    events = make_events(["success"]).drop(columns=["source_ip"])

    with pytest.raises(ValueError, match="Missing required columns"):
        analyze_dataframe(events)

def test_six_failures_generate_only_one_repeated_failure_alert():
    events = make_events(["failure"] * 6)

    alerts = analyze_dataframe(events)

    repeated = alerts[
        alerts["alert_type"] == "Repeated Authentication Failures"
    ]

    assert len(repeated) == 1
    assert repeated.iloc[0]["failure_count"] >= 5
