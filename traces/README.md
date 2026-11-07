# Sample trace

One real run through the harness, so the team can see what it records.

**`run_e8464be8ec`**
- **Prompt:** "What is 17 * 23? Ask a helper to double-check it."
- **Model:** Claude Opus 5.5 via OpenRouter, with no sandbox, so no shell or file tools.
- **What happened:** `agt_A` spawned a helper, `agt_A.1`, with its own system prompt. The helper checked the answer and messaged back, and `agt_A` gave the final answer, 391. It took 3 rounds and 6,894 tokens.

## Check it's genuine
It's signed with Ian's harness key, whose public key is:
```
t8LwF44lZ/SHTcg646rEt6u7SqyecS4tEBgYQ37Crm0=
```
From the repo root, after `pip install -e .`:
```bash
harness verify traces/run_e8464be8ec --public-key t8LwF44lZ/SHTcg646rEt6u7SqyecS4tEBgYQ37Crm0=
```
It should say `VERIFIED`, meaning nothing has changed since it was signed. Anyone who can edit this file could swap both the logs and the key, so for anything that matters, get the key from Ian directly. The `public_key.txt` in the folder is only a convenience copy, for the same reason.

## View it in Phoenix
Phoenix shows each agent nested under its parent, and each model call's full conversation:
```bash
pip install -e ".[trace]"
docker run -d --rm --name harness-phoenix -p 6006:6006 \
    -v harness-phoenix-data:/root/.phoenix arizephoenix/phoenix:version-20.26.1
harness --runs-dir traces export run_e8464be8ec --public-key t8LwF44lZ/SHTcg646rEt6u7SqyecS4tEBgYQ37Crm0=
```
Then open http://localhost:6006 and choose the `harness` project.

## Or read it in the terminal
```bash
harness trace traces/run_e8464be8ec --full --public-key t8LwF44lZ/SHTcg646rEt6u7SqyecS4tEBgYQ37Crm0=
```

| File | Contents |
|---|---|
| `ledger.jsonl` | Lineage: who created whom, with each agent's signed ID and config |
| `calls.jsonl` | Every prompt, response, tool call and message, in order |
| `*.head.json` | The signed end of each log, which catches cut-off or edited logs |
