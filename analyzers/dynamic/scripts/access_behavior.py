import os
import re
import logging
from concurrent.futures import ThreadPoolExecutor
from typing import List, Dict

# Setup logging (can be adjusted for centralized logging in production)
logging.basicConfig(
    level=logging.DEBUG, format="%(asctime)s - %(levelname)s - %(message)s"
)

# Regex patterns for suspicious activity (can be extended with more patterns)
MALICIOUS_FILE_PATTERN = r"(malicious|key|temp|AppData|Roaming|SysWow64)"
MALICIOUS_REGISTRY_PATTERN = r"(malicious|run|startup|system|AutoRun)"


# Function to detect suspicious file based on regex
def is_suspicious_file(file_path: str) -> bool:
    """
    Determines if a file path is suspicious based on regex.
    """
    return bool(re.search(MALICIOUS_FILE_PATTERN, file_path, re.IGNORECASE))


# Function to detect suspicious registry based on regex
def is_suspicious_registry(registry_key: str) -> bool:
    """
    Determines if a registry key is suspicious based on regex.
    """
    return bool(re.search(MALICIOUS_REGISTRY_PATTERN, registry_key, re.IGNORECASE))


# Function to simulate file access and log if suspicious
def monitor_file_access(file_path: str):
    """
    Monitors file access and logs suspicious access based on patterns.
    """
    try:
        # Simulate file access (you can replace this with actual logic)
        if is_suspicious_file(file_path):
            logging.warning(f"Suspicious file accessed: {file_path}")
        else:
            logging.info(f"File accessed: {file_path}")
    except Exception as e:
        logging.error(f"Error accessing file {file_path}: {e}")


# Function to simulate registry access and log if suspicious
def monitor_registry_access(registry_key: str):
    """
    Monitors registry access and logs suspicious registry access based on patterns.
    """
    try:
        # Simulate registry access (replace with actual registry access logic if needed)
        if is_suspicious_registry(registry_key):
            logging.warning(f"Suspicious registry accessed: {registry_key}")
        else:
            logging.info(f"Registry accessed: {registry_key}")
    except Exception as e:
        logging.error(f"Error accessing registry {registry_key}: {e}")


# Function to handle monitoring tasks with ThreadPoolExecutor for concurrency
def monitor_access_behavior(
    files: List[str], registry_keys: List[str]
) -> Dict[str, str]:
    """
    Monitors file and registry access concurrently using ThreadPoolExecutor.
    """
    results = {"access_logs": []}

    with ThreadPoolExecutor() as executor:
        futures = []

        # Submit tasks for file access monitoring
        for file_path in files:
            futures.append(executor.submit(monitor_file_access, file_path))

        # Submit tasks for registry key access monitoring
        for registry_key in registry_keys:
            futures.append(executor.submit(monitor_registry_access, registry_key))

        # Wait for all tasks to complete
        for future in futures:
            future.result()  # Collect the results or handle exceptions

    results["status"] = "completed"
    return results


# Example usage of the monitoring function
if __name__ == "__main__":
    # List of files and registry keys to monitor
    files_to_monitor = [
        "C:\\Users\\Admin\\AppData\\Roaming\\malicious_file.exe",
        "C:\\Windows\\System32\\drivers\\etc\\hosts",
        "C:\\temp\\config.txt",
        "C:\\ProgramData\\App\\settings.ini",
    ]

    registry_keys_to_monitor = [
        "HKLM\\Software\\MaliciousKey",
        "HKCU\\Software\\MyApp\\Settings",
        "HKCU\\Software\\Microsoft\\Windows\\Run\\malicious_app",
        "HKLM\\Software\\System\\AutoRun",
    ]

    result = monitor_access_behavior(files_to_monitor, registry_keys_to_monitor)
    logging.info(f"Monitoring completed with status: {result['status']}")
