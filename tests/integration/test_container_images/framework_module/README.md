# Framework module for container_images

These three files belong in the `wazuh_testing` framework package, at:

```text
wazuh_testing/modules/modulesd/container_images/
├── __init__.py     # PREFIX / WMODULES_PREFIX log prefixes
├── patterns.py     # log-line regexes used as FileMonitor anchors
└── db.py           # local-database query helper + table names
```

They are kept here, alongside the tests, so the change set is self-contained and reviewable in
one place. To run the suite, copy them into the installed `wazuh_testing` package (or install the
framework from a branch that already contains them):

```bash
DST=$(python -c "import wazuh_testing, os; print(os.path.dirname(wazuh_testing.__file__))")/modules/modulesd/container_images
mkdir -p "$DST"
cp __init__.py patterns.py db.py "$DST"/
```

This mirrors how `test_syscollector` consumes
`wazuh_testing/modules/modulesd/syscollector/patterns.py`.
