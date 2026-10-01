from datetime import datetime, timezone
import os
import pandas as pd
from pandas.errors import EmptyDataError, ParserError
import requests

REPO_FULL = os.environ.get("GITHUB_REPOSITORY", "")
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN")
CSV_FILE = "metrics/release_downloads.csv"
SCHEMA_COLUMNS = [
    "release_tag",
    "total_downloads",
    "asset_name",
    "size_bytes",
    "last_updated",
]


def fetch_release_stats():
  headers = {"Accept": "application/vnd.github+json"}
  if GITHUB_TOKEN:
    headers["Authorization"] = f"Bearer {GITHUB_TOKEN}"

  # Request up to 100 releases
  url = f"https://api.github.com/repos/{REPO_FULL}/releases?per_page=100"
  response = requests.get(url, headers=headers)
  response.raise_for_status()
  releases = response.json()

  now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
  records = []

  for release in releases:
    tag = release.get("tag_name")
    assets = release.get("assets", [])

    # Sum downloads and size across all assets in this release version
    total_downloads = sum(asset.get("download_count", 0) for asset in assets)
    total_size = sum(asset.get("size", 0) for asset in assets)
    asset_names = (
        ", ".join(asset.get("name") for asset in assets)
        if assets
        else "no assets"
    )

    records.append({
        "release_tag": tag,
        "total_downloads": total_downloads,
        "asset_name": asset_names,
        "size_bytes": total_size,
        "last_updated": now,
    })

  return records


def update_summary_data(records):
  os.makedirs(os.path.dirname(CSV_FILE), exist_ok=True)

  df_new = pd.DataFrame(records, columns=SCHEMA_COLUMNS)

  df_existing = pd.DataFrame(columns=SCHEMA_COLUMNS)
  if os.path.exists(CSV_FILE) and os.path.getsize(CSV_FILE) > 0:
    try:
      df_existing = pd.read_csv(CSV_FILE)
    except (EmptyDataError, ParserError):
      df_existing = pd.DataFrame(columns=SCHEMA_COLUMNS)

  # Place new updates first, then drop duplicates by release_tag.
  # This updates existing version rows with the latest numbers and appends new tags.
  df_combined = pd.concat([df_new, df_existing], ignore_index=True)
  df_combined.drop_duplicates(
      subset=["release_tag"], keep="first", inplace=True
  )

  # Sort by release tag if desired, maintaining schema column order
  df_combined = df_combined.reindex(columns=SCHEMA_COLUMNS)
  df_combined.to_csv(CSV_FILE, index=False)
  print(f"Updated {CSV_FILE} with {len(df_combined)} release version entries.")


if __name__ == "__main__":
  if not REPO_FULL:
    raise ValueError("GITHUB_REPOSITORY environment variable is missing.")
  data = fetch_release_stats()
  update_summary_data(data)
