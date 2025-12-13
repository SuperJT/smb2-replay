---
name: ruff-before-commit
enabled: true
event: bash
pattern: git\s+commit
action: warn
---

**Run Ruff before committing!**

Before committing, ensure code quality by running:

```bash
ruff check . --fix && ruff format .
```

This will:
- Fix auto-fixable lint issues
- Format code consistently
- Ensure import sorting

If there are unfixable issues, address them before committing.
