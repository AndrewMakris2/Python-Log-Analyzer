# advanced_log_analyzer.py

import re  # Import the regex module to allow pattern matching

def analyze_logs(log_file_path, keywords=None, patterns=None):
    """
    Analyzes a log file for specified keywords or regular expression patterns.

    Args:
        log_file_path (str): The path to the log file.
        keywords (list): A list of keywords to search for (case-insensitive).
        patterns (list): A list of regular expression patterns to match.

    Returns:
        list: A list of dictionaries, where each dictionary contains
              details of a found event.
    """
    # Default to empty lists if no keywords or patterns are provided
    if keywords is None:
        keywords = []
    if patterns is None:
        patterns = []

    found_events = []  # Stores all suspicious events found

    try:
        # Open the log file in read mode
        with open(log_file_path, 'r') as file:
            # Loop through each line with its line number (starting at 1)
            for line_number, line in enumerate(file, 1):

                # --- Keyword Search ---
                for keyword in keywords:
                    if keyword.lower() in line.lower():  # Case-insensitive match
                        found_events.append({
                            'line_number': line_number,
                            'type': 'Keyword Match',
                            'match': keyword,
                            'line': line.strip()
                        })

                # --- Regex Pattern Search ---
                for pattern in patterns:
                    if re.search(pattern, line):  # If regex finds a match
                        found_events.append({
                            'line_number': line_number,
                            'type': 'Regex Match',
                            'match': pattern,
                            'line': line.strip()
                        })

    # Error handling for missing files
    except FileNotFoundError:
        print(f"Error: The file at '{log_file_path}' was not found.")
        return []
    except Exception as e:
        # Catch-all for unexpected issues
        print(f"An unexpected error occurred: {e}")
        return []

    return found_events  # Return all collected suspicious events


if __name__ == '__main__':
    # --- Script Entry Point ---

    # Ask the user for the log file path instead of hardcoding it
    log_file = input("Enter the full path to the log file: ").strip()

    # Define suspicious keywords to look for
    suspicious_keywords = ['failed login', 'permission denied', 'unauthorized access']

    # Regex pattern to detect IPv4 addresses
    ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'

    # Call the analyzer with both keywords and regex patterns
    results = analyze_logs(log_file, keywords=suspicious_keywords, patterns=[ip_pattern])

    # --- Display Results ---
    if results:
        print(f"\nFound {len(results)} suspicious events:")
        for event in results:
            print("-" * 40)
            print(f"Line {event['line_number']} ({event['type']})")
            print(f"  Match: {event['match']}")
            print(f"  Full Line: {event['line']}")
    else:
        print("\nNo suspicious events found.")
