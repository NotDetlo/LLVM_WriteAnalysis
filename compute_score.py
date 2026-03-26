import statistics

alpha = 0.6
gamma = 0.4
threshold = 0.6

results_file = "build/results.txt"
secure_file = "build/secure_results.txt"

# =========================
# Step 1: Read secure functions
# =========================
secure_funcs = set()

with open(secure_file) as f:
    for line in f:
        name = line.strip()
        if name:
            secure_funcs.add(name)

# =========================
# Step 2: Read memory results
# =========================
functions = {}
current_func = None

with open(results_file) as f:
    for line in f:
        line = line.strip()

        if line.startswith("Function:"):
            current_func = line.split(":")[1].strip()
            functions[current_func] = {}

        elif "Write Frequency" in line:
            functions[current_func]["wf"] = float(line.split(":")[1])

        elif "Memory Intensity" in line:
            functions[current_func]["mi"] = float(line.split(":")[1])

# =========================
# Step 3: Z-score normalization prep
# =========================
wf_values = [v.get("wf", 0) for v in functions.values()]
mi_values = [v.get("mi", 0) for v in functions.values()]

wf_mean = statistics.mean(wf_values) if wf_values else 0
mi_mean = statistics.mean(mi_values) if mi_values else 0

wf_std = statistics.stdev(wf_values) if len(wf_values) > 1 else 1
mi_std = statistics.stdev(mi_values) if len(mi_values) > 1 else 1

# =========================
# Step 4: Compute score
# =========================
print("\nFunction\tScore\tMapping\tSensitive")

for func, vals in functions.items():

    wf = vals.get("wf", 0)
    mi = vals.get("mi", 0)

    # 🔥 Z-score normalization (KEY FIX)
    wf_norm = (wf - wf_mean) / wf_std if wf_std != 0 else 0
    mi_norm = (mi - mi_mean) / mi_std if mi_std != 0 else 0

    if func in secure_funcs:
        # ✅ Secure → always SRAM
        score = 1.0
        mapping = "SRAM"
        sens = 1
    else:
        sens = 0

        # 🔥 Score only for NON-secure functions
        score = alpha * wf_norm + gamma * mi_norm

        mapping = "SRAM" if score >= threshold else "FRAM"

    print(f"{func}\t{score:.3f}\t{mapping}\t{sens}")