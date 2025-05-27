# 🧩 Match & Menda

**Match & Menda** is a binary patching tool for fixing known vulnerabilities in ELF binaries.

---

## 📂 Project Structure

- `patching/function.py` — Core patching logic of Match & Menda  
- `run_magma.py` — Script to run Match & Menda on Magma binaries  
- `Testsuite/Magma/extra/` — Contains proof-of-vulnerability (PoV) data (e.g. in `PNG001`, `PNG004`, etc.)

---

## ⚙️ How to Use

### 🧪 First Evaluation (Magma)

To patch binaries from the refined Magma dataset:

```bash
python run_magma.py

## Second Evaluation (Karonte)

requires `ninja` to be installed in order to build `lief`.
