import sqlite3
from collections import Counter

def get_report():
    conn = sqlite3.connect('state_memory/state_memory.db')
    cursor = conn.cursor()

    try:
        cursor.execute("SELECT command FROM attack_logs")
        commands = [row[0] for row in cursor.fetchall()]

        total_commands = len(commands)
        top_commands = Counter(commands).most_common(5)
        recent_sessions = cursor.execute("SELECT * FROM sessions ORDER BY timestamp DESC LIMIT 10").fetchall()

        print(f"Total number of commands executed by attackers: {total_commands}")
        print("\nTop 5 most frequently attempted commands:")
        for command, count in top_commands:
            print(f"{command}: {count}")

        print("\nMost recent 10 sessions/interactions:")
        for session in recent_sessions:
            print(session)

    except sqlite3.Error as e:
        print(f"SQLite error: {e}")

    finally:
        conn.close()

if __name__ == "__main__":
    get_report()