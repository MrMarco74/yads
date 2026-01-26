"""
Date range filtering utilities for analytics and reporting pages.
"""
from datetime import datetime, timedelta
from typing import Optional, Tuple
from sqlmodel import select


def get_date_range_from_preset(preset: Optional[str]) -> Tuple[Optional[datetime], Optional[datetime]]:
    """
    Convert a preset string to actual date range.

    Args:
        preset: One of '1d', '7d', '30d', '90d', '1y', 'all', or None

    Returns:
        Tuple of (from_datetime, to_datetime). Both None for 'all' or invalid preset.
    """
    if not preset or preset == 'all':
        return None, None

    now = datetime.utcnow()
    to_dt = now

    preset_map = {
        '1d': timedelta(days=1),
        '7d': timedelta(days=7),
        '30d': timedelta(days=30),
        '90d': timedelta(days=90),
        '1y': timedelta(days=365),
    }

    delta = preset_map.get(preset)
    if delta:
        from_dt = now - delta
        return from_dt, to_dt

    return None, None


def parse_date_range(
    date_from: Optional[str] = None,
    date_to: Optional[str] = None,
    preset: Optional[str] = None
) -> Tuple[Optional[datetime], Optional[datetime]]:
    """
    Parse date range from query parameters.

    Priority:
    1. If explicit date_from/date_to are provided, use them
    2. Otherwise, use preset
    3. If neither, return None, None (no filtering)

    Args:
        date_from: ISO date string (YYYY-MM-DD)
        date_to: ISO date string (YYYY-MM-DD)
        preset: Preset string ('1d', '7d', '30d', '90d', '1y', 'all')

    Returns:
        Tuple of (from_datetime, to_datetime)
    """
    # If explicit dates provided, use them
    if date_from or date_to:
        from_dt = None
        to_dt = None

        if date_from:
            try:
                from_dt = datetime.strptime(date_from, "%Y-%m-%d")
            except ValueError:
                pass

        if date_to:
            try:
                # End of day for to_date
                to_dt = datetime.strptime(date_to, "%Y-%m-%d")
                to_dt = to_dt.replace(hour=23, minute=59, second=59)
            except ValueError:
                pass

        return from_dt, to_dt

    # Otherwise use preset
    return get_date_range_from_preset(preset)


def apply_date_filter_to_results(
    results: list,
    date_from: Optional[datetime],
    date_to: Optional[datetime],
    date_field: str = 'scanned_at'
) -> list:
    """
    Filter a list of ORM objects by date range.

    Args:
        results: List of ORM objects with a date field
        date_from: Start datetime (inclusive)
        date_to: End datetime (inclusive)
        date_field: Name of the date attribute on the objects

    Returns:
        Filtered list
    """
    if not date_from and not date_to:
        return results

    filtered = []
    for r in results:
        dt = getattr(r, date_field, None)
        if dt is None:
            continue

        if date_from and dt < date_from:
            continue
        if date_to and dt > date_to:
            continue

        filtered.append(r)

    return filtered


def build_date_filter_sql(
    date_from: Optional[datetime],
    date_to: Optional[datetime],
    column_name: str = 'scanned_at'
) -> Tuple[str, dict]:
    """
    Build SQL WHERE clause fragment for date filtering.

    Args:
        date_from: Start datetime
        date_to: End datetime
        column_name: Name of the date column

    Returns:
        Tuple of (SQL fragment, params dict)
        SQL fragment will be empty string if no filtering needed.
    """
    conditions = []
    params = {}

    if date_from:
        conditions.append(f"{column_name} >= :date_from")
        params['date_from'] = date_from

    if date_to:
        conditions.append(f"{column_name} <= :date_to")
        params['date_to'] = date_to

    if conditions:
        return " AND ".join(conditions), params

    return "", {}


def get_date_range_display(
    date_from: Optional[datetime],
    date_to: Optional[datetime],
    preset: Optional[str] = None
) -> str:
    """
    Get a human-readable display string for the date range.

    Args:
        date_from: Start datetime
        date_to: End datetime
        preset: Optional preset that was used

    Returns:
        Human-readable string like "Last 7 Days" or "Jan 1 - Jan 31, 2024"
    """
    preset_labels = {
        '1d': 'Last 24 Hours',
        '7d': 'Last 7 Days',
        '30d': 'Last 30 Days',
        '90d': 'Last 90 Days',
        '1y': 'Last Year',
        'all': 'All Time',
    }

    if preset and preset in preset_labels:
        return preset_labels[preset]

    if not date_from and not date_to:
        return 'All Time'

    fmt = "%b %d, %Y"
    if date_from and date_to:
        return f"{date_from.strftime(fmt)} - {date_to.strftime(fmt)}"
    elif date_from:
        return f"From {date_from.strftime(fmt)}"
    elif date_to:
        return f"Until {date_to.strftime(fmt)}"

    return 'All Time'
