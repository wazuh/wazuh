# Test description

## Summary
This test is intended to make sure that there are no false positives related to the `bsdutils` package in Ubuntu.
The candidates are discarded because the OS isn't found in the platforms' array.

## Steps

- 001: The information of the OS is set, no output is expected
- 002: the `bsdutils` package is inserted. The logs that reject the candidates due to the plarform are expected.
