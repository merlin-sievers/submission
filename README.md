# 🧩 Match & Mend

**Match & Mend** is a binary patching tool for fixing known vulnerabilities in ELF binaries.

---

## 📂 Project Structure

- `patching/function.py` — Core patching logic of Match & Mend  

---

## ⚙️ How to Use

### 🧪 First Evaluation (Magma)


Requires manual building and patching of the targets.
Automation of this process is currently work in progress.







### 🧪 Second Evaluation (Karonte)

requires `ninja` to be installed in order to build `lief`.
You also need uv: https://docs.astral.sh/uv/

To run, execute:

```
uv run ./evaluate-karonte.py
```
