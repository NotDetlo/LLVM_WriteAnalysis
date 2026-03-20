# LLVM Security Analysis Pass

This project implements an LLVM-based analysis pass to evaluate memory behavior and security sensitivity of functions in a program.

## 🔍 Features

- Computes **Write Frequency**
- Computes **Memory Intensity**
- Calculates **Security Sensitivity Score**
- Classifies functions as **Sensitive / Non-sensitive**
- Suggests memory mapping (e.g., SRAM / FRAM)

## 📊 Metrics Explained

- **Instruction Count** → Total instructions in a function  
- **Store Count** → Number of write operations  
- **Load Count** → Number of read operations  

- **Write Frequency** = Store Count / Instruction Count  
- **Memory Intensity** = (Load + Store) / Instruction Count  

- **Security Score** → Based on memory behavior and access patterns  

## ⚙️ How to Build

```bash
mkdir build
cd build
cmake ..
make