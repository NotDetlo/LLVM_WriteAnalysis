alpha = 0.4
beta = 0.4
gamma = 0.2
threshold = 0.5

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
# Step 3: Compute score
# =========================
print("\nFunction\tScore\tMapping\tSensitive")

for func, vals in functions.items():

    wf = vals.get("wf", 0)
    mi = vals.get("mi", 0)

    # 🔥 NEW: get sensitivity from file
    sens = 1.0 if func in secure_funcs else 0.0

    score = alpha*wf + beta*sens + gamma*mi

    mapping = "SRAM" if score >= threshold else "FRAM"

    print(f"{func}\t{score:.3f}\t{mapping}\t{int(sens)}")