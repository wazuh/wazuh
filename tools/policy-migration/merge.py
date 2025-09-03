import pandas as pd

# Load both files
df4 = pd.read_csv("4x.txt", sep="|", names=["Id", "Result4x"], dtype=str)
df5 = pd.read_csv("5x.txt", sep="|", names=["Id", "Result5x"], dtype=str)

# Merge on Id (outer join to include missing ones)
merged = pd.merge(df4, df5, on="Id", how="outer")

# Fill missing values with blanks
merged = merged.fillna("")

# Add comparison column with emojis (case-insensitive)
def compare_results(row):
    r4 = row["Result4x"].strip().lower()
    r5 = row["Result5x"].strip().lower()
    if not r4 or not r5:
        return ""   # no comparison possible
    return "\u2705" if r4 == r5 else "🔴"

merged["Match"] = merged.apply(compare_results, axis=1)

# Save output
output_path = "merged-results.txt"
with open(output_path, "w", encoding="utf-8") as f:
    f.write("|Id|4.x result|5.x result|Match|\n")
    for _, row in merged.iterrows():
        f.write(f"|{row['Id']}|{row['Result4x']}|{row['Result5x']}|{row['Match']}|\n")

print(f"✅ Done! Results saved to {output_path}")
