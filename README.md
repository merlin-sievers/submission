# 🧩 Match & Mend

**Match & Mend** is a binary patching tool for fixing known vulnerabilities in ELF binaries.

---

## 📂 Project Structure

- `patching/function.py` — Core patching logic of Match & Mend  
- `run_magma.py` — Script to run Match & Mend on Magma binaries  
- `Testsuite/Magma/extra/` — Contains proof-of-vulnerability (PoV) data (e.g. in `PNG001`, `PNG004`, etc.)

---

## ⚙️ How to Use

### 🧪 First Evaluation (Magma) (work in progress)

To patch binaries from the refined Magma dataset:

```bash
python run_magma.py
```

Using the unit test of the open-source libraries you can test if the patched binary is still functional (Automation due to dependencies of libraries still work in progress)

Using the Fuzzing Harness of the Magma Dataset (https://github.com/HexHive/magma) and the PoVs collected in 'Testsuite/Magma/extra/...' you can test if the vulnerability has been fixed.







### 🧪 Second Evaluation (Karonte)

requires `ninja` to be installed in order to build `lief`.
