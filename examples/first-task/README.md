# First task: a small local repair

This directory is an intentionally unfinished exercise, not bridge runtime
code. The starting version fails three of five tests. It needs only Python's
standard library and contains no real project data.

After [installing HarnessLift](../../README.md#quick-start), copy `slugify.py`
and `test_slugify.py` into a new empty directory. Open a terminal there, run
`harnesslift`, and use `/model` to select a model your account can use.

Give Claude Code this task, choosing `python` instead of `python3` if that is
your Python command on Windows:

```text
Fix slugify.py so all five existing tests pass. Read both files first.
Keep the tests unchanged and use only Python's standard library.
Run python3 -m unittest -q before and after your change.
Do not use the network, install packages, or modify other files.
Finish with a brief result.
```

Keep normal tool permissions and review proposed actions. The desired outcome
is a local edit followed by five passing tests. A successful result establishes
this small tool workflow, not general model quality or unattended reliability.
Model requests use your provider account's quota; relevant task context reaches
OpenAI through the local bridge.

If you want to report a result, use the [first-run form](https://github.com/Jcstack/harnesslift/issues/new?template=trial_feedback.yml).
Platform, versions and pass/blocked are enough. Do not upload credentials,
private prompts, transcripts, quota panels or logs.
