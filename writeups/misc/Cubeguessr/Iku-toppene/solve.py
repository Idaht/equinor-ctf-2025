import subprocess
import argparse

def run_bedrock_parallel(n, start, end, bedrock="./bedrock"):
    procs = []

    for i in range(n):
        cmd = [bedrock, "full", str(i), str(n), str(start), str(end)]
        print("Starting:", " ".join(cmd))
        p = subprocess.Popen(cmd)
        procs.append((i, p))

    print(f"\nLaunched {n} processes. Waiting for them to finish...\n")

    for i, p in procs:
        rc = p.wait()
        print(f"{bedrock} full {i} {n} {start} {end} finished with exit code {rc}")

    print("\nAll processes completed.")

if __name__ == "__main__":
    ap = argparse.ArgumentParser(
        description="Launch bedrock search in parallel across N shards."
    )
    ap.add_argument("N", type=int, help="number of parallel processes / shards")
    ap.add_argument("--start", type=int, default=0, help="ring start (chunks from spawn)")
    ap.add_argument("--end", type=int, default=1875000, help="ring end (chunks from spawn)")
    ap.add_argument("--bedrock", default="./bedrock", help="path to bedrock binary")
    args = ap.parse_args()

    if args.N < 1:
        raise SystemExit("Error: N must be a positive integer.")

    run_bedrock_parallel(args.N, args.start, args.end, args.bedrock)
