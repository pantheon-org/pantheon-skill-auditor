# Remediation Planning Guide

Guide for turning skill quality audit results into an improvement plan.

## The Plan Format

There is one remediation plan: `Remediation.md`, written by `pantheon-skill-auditor evaluate --store`.
It sits beside `Analysis.md` and `audit.json` in `skills/<domain>/<skill-name>/.audits/<date>/`.
No tool reads it back, so it is a working document for you, not a checked artifact.

```bash
pantheon-skill-auditor evaluate <domain>/<skill-name> --json --store
```

`Remediation.md` holds:

- The current grade and total.
- One section per dimension that scored below its maximum, largest shortfall first.
- Per section: the score, the points available, what happened, the likely cause and the fix.

## Using It

1. Read the top section first; it has the most points available.
2. Open the files the likely cause points at and make the smallest edit that closes the gap.
3. Re-run the audit and compare the dimension score against the points listed.
4. Stop once the skill reaches the target grade (A, 126/140 or higher).

## When To Add Detail

The generated plan is generic per dimension. Add your own notes (in the PR description, not in the skill) when:

- Two dimensions share a cause, such as a short `description` lowering D4 and D7.
- A fix has a cost, such as moving content to `references/` for D5 while `SKILL.md` links must stay valid.
- The target is more than one grade away, so the work needs ordering.

Size each step S, M or L and state the expected score change, so the result can be checked against the next audit.

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
