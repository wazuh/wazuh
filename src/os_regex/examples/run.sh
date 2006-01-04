make
perl ./validate.pl "./regex" tests/true.tests FALSE
perl ./validate.pl "./regex" tests/false.tests TRUE
perl ./validate.pl "./regex" tests/true.regex FALSE
perl ./validate.pl "./regex" tests/false.regex TRUE
perl ./validate.pl "./regex_str" tests/str.regex FALSE
