# Skill Conventions

This repository follows the Codex skill design model. A skill is a compact,
self-contained onboarding guide that gives Codex specialized workflow,
tooling, domain knowledge, and reusable resources for a class of tasks.

`skills/` should contain real skill directories plus this conventions file
only. Do not store scaffold templates under `skills/`.

## Design Principles

- Treat context as a shared budget. Put only the instructions Codex needs in
  `SKILL.md`; move detailed material into progressive resources.
- Assume Codex is already capable. Add domain-specific process, constraints,
  tool usage, validation expectations, and non-obvious project knowledge.
- Set the right degree of freedom. Use prose for flexible judgment, pseudocode
  or parameters for preferred patterns, and scripts for fragile or repetitive
  operations that need deterministic behavior.
- Design for another Codex instance to succeed without hidden context.
- Validate skills against realistic prompts and raw artifacts, not just
  structure.

## Layout

Use this structure for each real skill:

```text
skills/
  skill-name/
    SKILL.md
    agents/
      openai.yaml
    scripts/
    references/
    assets/
```

Required:

- `SKILL.md`: frontmatter plus concise Markdown instructions.

Recommended when directly useful:

- `agents/openai.yaml`: UI metadata and product-facing skill configuration.
- `scripts/`: deterministic helpers for repeated or fragile operations.
- `references/`: documentation Codex should load only when needed.
- `assets/`: files used in outputs, such as templates, images, icons, fonts,
  or boilerplate.

Only create resource directories that the skill actually needs.

## SKILL.md

Every `SKILL.md` must start with YAML frontmatter containing `name` and
`description`:

```yaml
---
name: skill-name
description: Clear trigger description for when Codex should use this skill.
---
```

Rules:

- Use lowercase letters, digits, and hyphens for `name`; keep it under 64
  characters and match the folder name exactly.
- Make `description` the primary trigger surface. Include what the skill does
  and the concrete prompts, contexts, files, tools, or tasks that should cause
  Codex to use it.
- Put all "when to use" information in `description`, not only in the body. The
  body is loaded only after the skill triggers.
- Treat `name` and `description` as the only trigger contract. Avoid extra
  frontmatter fields; product-specific metadata belongs in `agents/openai.yaml`.
- Keep the body concise and procedural, ideally under 500 lines.
- Use imperative guidance with concrete decision points.
- Link directly from `SKILL.md` to every reference file Codex may need.

## Progressive Disclosure

Skills should load information in layers:

1. Metadata: `name` and `description` are always available for triggering.
2. `SKILL.md` body: loaded after the skill triggers.
3. Bundled resources: read or executed only when needed.

Use this pattern to keep the active context lean:

- Keep core workflow and selection guidance in `SKILL.md`.
- Move detailed playbooks, schemas, API notes, examples, and policy material to
  `references/`.
- Keep reference files one level deep under `references/`.
- Add a short table of contents to reference files longer than roughly 100
  lines.
- Include grep/search hints in `SKILL.md` for very large references.
- Do not duplicate long content between `SKILL.md` and `references/`.

## Bundled Resources

Use `scripts/` for executable helpers when the same code would otherwise be
rewritten repeatedly, or when correctness depends on a precise sequence. Test
added scripts by running them.

Use `references/` for material Codex should read into context as needed:
workflow guides, schemas, threat models, API documentation, checklists, or
domain rules.

Use `assets/` for files Codex should use in produced outputs rather than read
as guidance: document templates, slide templates, images, icons, fonts,
fixtures, or starter projects.

## Agents Metadata

`agents/openai.yaml` provides UI metadata and product-facing configuration. Keep
it consistent with `SKILL.md` whenever the skill changes.

Minimal example:

```yaml
interface:
  display_name: "Skill Name"
  short_description: "Short user-facing description"
  default_prompt: "Use $skill-name to ..."
```

Rules:

- Quote string values and keep keys unquoted.
- Make `display_name` human-facing and specific.
- Keep `short_description` brief, normally 25-64 characters.
- Make `default_prompt` a short example prompt that explicitly mentions
  `$skill-name`.
- Include optional `icon_small`, `icon_large`, `brand_color`,
  `dependencies.tools`, or `policy.allow_implicit_invocation` only when the
  product surface intentionally supports them.

## Host Integration Contract

Any runtime that consumes these skills should honor the Codex model:

- Discover only real skill directories with `SKILL.md`.
- Parse YAML frontmatter robustly and read only `name` and `description` for
  triggering. Ignore unsupported metadata rather than making otherwise valid
  skills unusable.
- Treat `description` as the trigger contract.
- Load the `SKILL.md` body only after the skill triggers.
- Let bundled resources remain lazy; do not eagerly load entire skill trees
  into context.
- Keep `agents/openai.yaml` separate from prompt instructions unless the host
  explicitly needs product metadata.

Implementation shortcuts that make a skill valid only for one local parser
should be treated as defects, not conventions.

## Creation Workflow

When creating or updating a skill:

1. Understand concrete user prompts and artifacts that should trigger it.
2. Identify reusable resources: scripts, references, and assets.
3. Initialize from the Codex skill scaffold when available, or create the same
   structure manually.
4. Write `SKILL.md` with trigger language in `description` and concise
   procedural guidance in the body.
5. Generate or update `agents/openai.yaml` from the final `SKILL.md`.
6. Validate structure with the Codex skill validator when available.
7. Forward-test complex skills with realistic prompts and raw artifacts.
8. Iterate when real usage exposes missing guidance or unnecessary context.

## Validation

A skill is not done until it passes both structural and behavioral checks:

- `SKILL.md` has valid frontmatter with `name` and `description`.
- The folder name matches `name`.
- `description` clearly covers intended trigger cases without relying on body
  text.
- `agents/openai.yaml` matches the skill and has a useful `default_prompt`.
- Scripts run successfully on representative inputs.
- References are discoverable from `SKILL.md`.
- Realistic prompts trigger the skill and lead Codex toward the intended
  workflow.
- Non-trigger prompts avoid accidental activation.

## Do Not Include

Keep skill folders focused on what Codex needs to perform the task. Avoid
auxiliary documentation unless it is directly used by the skill workflow:

- `README.md`
- `INSTALLATION_GUIDE.md`
- `QUICK_REFERENCE.md`
- `CHANGELOG.md`
- process notes that explain how the skill was authored
