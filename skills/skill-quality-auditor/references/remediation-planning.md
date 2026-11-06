# Remediation Planning Guide

Guide for acting on the remediation output of a skill quality audit.

## The Loop

`Remediation.md` is a view of `audit.json`, written by `evaluate --store`. It is not a plan you write, and no tool reads it back.

```bash
pantheon-skill-auditor evaluate <domain>/<skill-name> --json --store
```

1. Read `Remediation.md` in the `.audits/<date>/` folder, starting with the dimension that has the most points available.
2. Make the smallest edit that closes the gap.
3. Re-run the audit and compare the dimension score.
4. Stop at the target grade (A, 126/140 or higher).

## Common Remediation Patterns

### Pattern 1: Anti-Pattern Addition

For D3 (Anti-Pattern Quality):

````markdown
## Anti-Patterns

### NEVER: [Action]

**WHY**: [Reason]

**BAD**:
```[language]
[bad code]
```

**GOOD**:
```[language]
[good code]
```
````

### Pattern 2: Reference Creation

For D5 (Progressive Disclosure):

1. Create a `references/` directory in the skill.
2. Extract detailed content from `SKILL.md`.
3. Add a navigation table to `SKILL.md`:

```markdown
## Quick Reference

| Topic | Reference |
|-------|-----------|
| Topic Name | [references/topic.md](references/topic.md) |
```

### Pattern 3: Trigger Expansion

For D7 (Pattern Recognition), update the frontmatter description:

```yaml
---
name: skill-name
description: |
  [Core description]. Use when: [trigger phrases].

  Keywords: [comma-separated keywords]
---
```

## Verification

```bash
pantheon-skill-auditor evaluate <domain>/<skill-name> --json
rumdl check skills/<domain>/<skill-name>
```

## Related References

- `framework-dimensions.md` - Understanding the dimensions
- `framework-scoring-rubric.md` - How scores are calculated
- `aggregation-pattern.md` - For larger consolidation efforts
