import sys
from crew import build_crew

def main():
    if len(sys.argv) != 2:
        print("Usage: python main.py <ip>")
        sys.exit(1)

    ip = sys.argv[1]
    crew = build_crew(ip)
    result = crew.kickoff()
    print("\n=== RESULT ===\n")
    print(result)

if __name__ == "__main__":
    main()
