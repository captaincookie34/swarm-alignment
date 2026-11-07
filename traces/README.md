# Sample traces

Real runs through the harness, so the team can see what it records. Both used Claude Opus 5.5 via OpenRouter.

**`run_01M6VJP0150BWXZ2HS9C1TQ45H`: helpers build a small package** (start here)
- **Prompt:** build `fizzbuzz.py`, `leap.py` and `roman.py`, each written and tested by its own helper agent, then write and run a combined test.
- **Setup:** in the Docker sandbox, so the agents had shell and file tools. Their files are in `workspace/`.
- **What happened:**
  1. **Round 1:** the main agent tried to spawn three helpers at once. The third was refused, because the limit is two spawns per round.
  2. **Rounds 2 to 4:** the helpers wrote and tested their modules and messaged back, and the main agent spawned the third helper in round 3.
  3. **Round 5:** the main agent wrote `test_all.py`. Its first run failed because of a mistake in its own expected answer, which it fixed.
- **Size:** 4 agents, 5 rounds and 68,040 tokens. IDs use the current format, such as `agt_ts65x2_01M6VJP0AKA14QH665N86R4SPW.1`, shown as `agt_…4SPW.1`.

**`run_e8464be8ec`: a helper checks an answer**
- **Prompt:** "What is 17 * 23? Ask a helper to double-check it."
- **Setup:** no sandbox, so no shell or file tools.
- **What happened:** `agt_A` spawned a helper, `agt_A.1`, which checked the answer and messaged back, and `agt_A` gave the final answer, 391. It took 3 rounds and 6,894 tokens.
- **Old ID format:** this run was recorded before IDs became globally unique, so its `agt_A` IDs are the old format, which still verifies.

## Check they're genuine
Both are signed with Ian's harness key, whose public key is:
```
t8LwF44lZ/SHTcg646rEt6u7SqyecS4tEBgYQ37Crm0=
```
From the repo root, after `pip install -e .`:
```bash
harness verify traces/run_01M6VJP0150BWXZ2HS9C1TQ45H --public-key t8LwF44lZ/SHTcg646rEt6u7SqyecS4tEBgYQ37Crm0=
```
Each should say `VERIFIED`, meaning nothing has changed since it was signed. Anyone who can edit this file could swap both the logs and the key, so for anything that matters, get the key from Ian directly. The `public_key.txt` in each folder is only a convenience copy, for the same reason.

## View them in Phoenix
Phoenix shows each agent nested under its parent, and each model call's full conversation:
```bash
pip install -e ".[trace]"
docker run -d --rm --name harness-phoenix -p 6006:6006 \
    -v harness-phoenix-data:/root/.phoenix arizephoenix/phoenix:version-20.26.1
harness --runs-dir traces export --all --public-key t8LwF44lZ/SHTcg646rEt6u7SqyecS4tEBgYQ37Crm0=
```
Then open http://localhost:6006 and choose the `harness` project.

## Or read them in the terminal
```bash
harness trace traces/run_01M6VJP0150BWXZ2HS9C1TQ45H --full --public-key t8LwF44lZ/SHTcg646rEt6u7SqyecS4tEBgYQ37Crm0=
```

| File | Contents |
|---|---|
| `ledger.jsonl` | Lineage: who created whom, with each agent's signed ID and config |
| `calls.jsonl` | Every prompt, response, tool call and message, in order |
| `*.head.json` | The signed end of each log, which catches cut-off or edited logs |
| `workspace/` | Files the agents made, for sandbox runs |
