# advanced_log_analyzer.py

import re

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
    if keywords is None:
        keywords = []
    if patterns is None:
        patterns = []

    found_events = []

    try:
        with open(log_file_path, 'r') as file:
            for line_number, line in enumerate(file, 1):
                # Search for keywords
                for keyword in keywords:
                    if keyword.lower() in line.lower():
                        found_events.append({
                            'line_number': line_number,
                            'type': 'Keyword Match',
                            'match': keyword,
                            'line': line.strip()
                        })

                # Search for regex patterns
                for pattern in patterns:
                    if re.search(pattern, line):
                        found_events.append({
                            'line_number': line_number,
                            'type': 'Regex Match',
                            'match': pattern,
                            'line': line.strip()
                        })

    except FileNotFoundError:
        print(f"Error: The file at '{log_file_path}' was not found.")
        return []
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return []

    return found_events

if __name__ == '__main__':
    # Example Usage:
    log_file = 'sample.log'
    suspicious_keywords = ['failed login', 'permission denied', 'unauthorized access']
    ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b' # Matches IPv4 addresses

    results = analyze_logs(log_file, keywords=suspicious_keywords, patterns=[ip_pattern])

    if results:
        print(f"Found {len(results)} suspicious events:")
        for event in results:
            print("-" * 40)
            print(f"Line {event['line_number']} ({event['type']})")
            print(f"  Match: {event['match']}")
            print(f"  Full Line: {event['line']}")
    else:
        print("No suspicious events found.")