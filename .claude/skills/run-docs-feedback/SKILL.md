---
name: run-docs-feedback
description: Serve a repo's markdown docs for review with docs-feedback, then continuously watch for comments and edits the reviewer leaves and apply the requested changes. Use to start a docs review session, or whenever the user wants to comment on / edit documentation in the browser and have the agent make the changes.
version: 0.3.0
---

# Run docs-feedback

Turn a documentation review into a tight loop: serve the docs, keep the server attached, watch its output, act on each comment or edit, report back on it, resume watching.

## Start the session

1. Treat the current working directory as the docs root unless the user names a directory or specific files.
2. Start the server in a persistent terminal session and keep stdout attached — do not redirect or discard it:

   ```sh
   npx docs-feedback@latest            # all markdown under the cwd
   npx docs-feedback@latest README.md  # only these files
   ```

   Use `--port N` if 4180 is taken, `--open` to launch the browser.
3. Read the printed URL and tell the user the docs are ready for review. Keep the task active and the server running.

`GET <url>/__docs-feedback/status` answers `{"status":"ok"}` when the loop is live.

## Watch and react

Poll the server output frequently while waiting. Three block types appear:

```text
[docs-feedback:new]        a comment on a location in a file
...
[/docs-feedback:new]

[docs-feedback:edit]       an edit the reviewer already saved to disk, as a unified diff
...
[/docs-feedback:edit]

[docs-feedback:reply]      the reviewer answering you on an item you already reported on
...
[/docs-feedback:reply]
```

## Report back

Every item has a status the reviewer watches in the browser. Send updates with `PATCH` and a JSON body; `reply` is plain text, a few lines at most, and lands under the item in the browser.

```sh
patch() { curl -s -X PATCH "$URL/__docs-feedback/$1" -H 'content-type: application/json' -d "$2"; }
```

- **Picking an item up** — if the work will take more than a moment, say what you are about to do:

  ```sh
  patch "$ID" '{"status":"working","reply":"Rewriting the Encryption paragraph and the matching CLI help."}'
  ```

- **Done** — say what changed and where: files touched, and anything left undone:

  ```sh
  patch "$ID" '{"status":"resolved","reply":"README.md:336 now says ssh-agent cannot work.\nsrc/cli.ts: help string updated to match."}'
  ```

- **Cannot or should not make the change** — say why and what you need from the reviewer:

  ```sh
  patch "$ID" '{"status":"declined","reply":"The doc and src/config.ts disagree on the default port. Which is right?"}'
  ```

`resolved` and `declined` are terminal. A bare `curl -X PATCH "$URL/__docs-feedback/$ID"` with no body still means resolved, but a reply is always better than silence.

## Act on each block

For every **new** block:

1. Read the full record from `.docs-feedback/feedback.jsonl` (match the `id`).
2. Open `file` at the given line range; `section` is the heading chain and `quote` is the exact text the reviewer selected.
3. If it is more than a quick fix, report `working` first.
4. Make the change the `instruction` asks for — in the doc, and wherever the doc is a spec for code, in the code too. Keep it to what was asked; preserve the author's voice and unrelated content.
5. If the instruction is a question, answer it by improving the doc where the question arose, and put the answer in the reply.
6. Report `resolved` with what changed, or `declined` with why.

For every **edit** block:

1. The file on disk already contains the change. Read the diff (and the optional `note`).
2. Check whether anything else must follow: other docs that repeat the changed text, code or tests the doc specifies, CLI help strings that mirror it. Apply those.
3. Report `resolved` the same way, listing the follow-up changes you made (or "nothing else needed").

For every **reply** block:

1. The reviewer has answered on an existing item — the `id` is one you have seen; `re:` is the original instruction (or edit), `was:` your last status and reply. The item is pending again.
2. Read the `reply` as the next instruction on the same location: a correction ("not quite"), more detail, or the answer to a question you asked when you declined.
3. Act on it the same way as a new block, then report `resolved` or `declined` again with `PATCH`. A thread can go back and forth until it is resolved.

The browser reloads the rendered file automatically when it changes on disk. Comments anchored to a selection stay highlighted in the document, coloured by status; everything else — the comment, edits, status changes, your replies, the reviewer's replies — is in the Threads pane, so the reviewer sees your progress without being told.

Process ids once even if the same output is returned by later polls. Never leave an item you looked at silently pending: resolve it or decline it with a reason.

## End the session

Stop only when the user asks or the surrounding task ends. Terminate the server cleanly and summarize resolved, declined, and still-pending ids.
