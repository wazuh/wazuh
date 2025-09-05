import pandas as pd
import sys, os, glob, re

def main():
    if len(sys.argv) < 5 or sys.argv[1] in ("-h", "--help"):
        print("Usage: python merge.py <4x_file> <5x_file> <5x_fix_file> <logs_dir_or_fixlog>")
        return

    if not (os.path.isfile(sys.argv[1]) and os.path.isfile(sys.argv[2]) and os.path.isfile(sys.argv[3])):
        print("Usage: python merge.py <4x_file> <5x_file> <5x_fix_file> <logs_dir_or_fixlog>")
        return

    df4 = pd.read_csv(sys.argv[1], sep="|", names=["Id", "Result4x"], dtype=str)
    df5 = pd.read_csv(sys.argv[2], sep="|", names=["Id", "Result5x"], dtype=str)
    df5fix = pd.read_csv(sys.argv[3], sep="|", names=["Id", "Result5xFix"], dtype=str)

    fix_ids = set()
    logs_arg = sys.argv[4]
    if os.path.isdir(logs_arg):
        candidates = sorted(glob.glob(os.path.join(logs_arg, "*fixlog*.txt")))
        if not candidates:
            print("Usage: python merge.py <4x_file> <5x_file> <5x_fix_file> <logs_dir_or_fixlog>")
            return
        log_path = candidates[0]
    elif os.path.isfile(logs_arg):
        log_path = logs_arg
    else:
        print("Usage: python merge.py <4x_file> <5x_file> <5x_fix_file> <logs_dir_or_fixlog>")
        return

    try:
        with open(log_path, "r", encoding="utf-8", errors="ignore") as lf:
            lines = lf.readlines()
        ids = []
        for line in lines:
            s = line.strip()
            if s.startswith("policy_list:") or s.startswith("policy_list_warnings:"):
                ids.extend(re.findall(r"\b\d+\b", s))
        fix_ids = set(ids)
    except Exception:
        print("Usage: python merge.py <4x_file> <5x_file> <5x_fix_file> <logs_dir_or_fixlog>")
        return

    merged = pd.merge(df4, df5, on="Id", how="outer")
    merged = pd.merge(merged, df5fix, on="Id", how="outer")
    merged = merged.fillna("")

    def compare_results_5xfix(row):
        r4 = row["Result4x"].strip().lower()
        r5f = row["Result5xFix"].strip().lower()
        if not r4 or not r5f:
            return ""
        return "\u2705" if r4 == r5f else "🔴"

    def compare_results_5x(row):
        r4 = row["Result4x"].strip().lower()
        r5 = row["Result5x"].strip().lower()
        if not r4 or not r5:
            return ""
        return "\u2705" if r4 == r5 else "🔴"

    merged["Match5x"] = merged.apply(compare_results_5x, axis=1)
    merged["Match5xFix"] = merged.apply(compare_results_5xfix, axis=1)

    # Decide output path based on fixlog name and logs directory (no defaults)
    logs_dir = logs_arg if os.path.isdir(logs_arg) else os.path.dirname(log_path)
    base = os.path.basename(log_path)
    if base.endswith("_fixlog.txt"):
        out_name = base[:-len("_fixlog.txt")] + "_resultlog.txt"
    else:
        name_no_ext, _ = os.path.splitext(base)
        out_name = name_no_ext + "_resultlog.txt"
    output_path = os.path.join(logs_dir, out_name)
    # Summary metrics
    is_fix = merged['Id'].astype(str).str.strip().isin(fix_ids)
    good_fix = int(((merged['Match5x'] == '🔴') & (merged['Match5xFix'] == '✅') & is_fix).sum())
    bad_fix = int(((merged['Match5x'] == '✅') & (merged['Match5xFix'] == '🔴') & is_fix).sum())
    non_fix_bad = int(((merged['Match5xFix'] == '🔴') & (~is_fix)).sum())
    non_fix_good = int(((merged['Match5xFix'] == '✅') & (~is_fix)).sum())
    with open(output_path, "w", encoding="utf-8") as f:
        f.write("|Id|4.x result|5.x result|4.x vs 5.x|5.x fix result|4.x vs 5.x fix|\n")
        for _, row in merged.iterrows():
            _id = str(row['Id']).strip()
            if _id in fix_ids:
                _id = "*" + _id
            f.write(f"|{_id}|{row['Result4x']}|{row['Result5x']}|{row['Match5x']}|{row['Result5xFix']}|{row['Match5xFix']}|\n")
        f.write("\n")
        f.write(f"Good fix | {good_fix}\n")
        f.write(f"Bad fix | {bad_fix}\n")
        f.write(f"Non-fix bad | {non_fix_bad}\n")
        f.write(f"Non-fix good | {non_fix_good}\n")
        f.write("\n")
        mismatched_ids_series = merged.loc[merged['Match5xFix'] == '🔴', 'Id'].astype(str).str.strip()
        mismatched_ids = [s for s in mismatched_ids_series if s]
        try:
            mismatched_ids_sorted = [str(i) for i in sorted({int(s) for s in mismatched_ids})]
        except ValueError:
            mismatched_ids_sorted = sorted(set(mismatched_ids))
        f.write(f"Missmatch_after_fix: {', '.join(mismatched_ids_sorted)}\n")

    print(f"✅ Done! Results saved to {output_path}")

if __name__ == "__main__":
    main()
