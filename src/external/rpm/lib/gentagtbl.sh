#!/bin/sh

cat << EOF
static const struct headerTagTableEntry_s rpmTagTable[] = {
EOF

${AWK} '/[\t ](RPMTAG_[A-Z0-9]*)[ \t]+([0-9]*)/ && !/internal/ && !/unimplemented/ {
	tt = "NULL"
	ta = "ANY"
	ext = "0"
	if ($5 == "c") {
		tt = "CHAR"
		ta = "SCALAR"
	}
	if ($5 == "c[]") {
		tt = "CHAR"
		ta = "ARRAY"
	} 
	if ($5 == "h") {
		tt = "INT16"
		ta = "SCALAR"
	}
	if ($5 == "h[]") {
		tt = "INT16"
		ta = "ARRAY"
	}
	if ($5 == "i") {
		tt = "INT32"
		ta = "SCALAR"
	}
	if ($5 == "i[]") {
		tt = "INT32"
		ta = "ARRAY"
	}
	if ($5 == "l") {
		tt = "INT64"
		ta = "SCALAR"
	}
	if ($5 == "l[]") {
		tt = "INT64"
		ta = "ARRAY"
	}
	if ($5 == "s") {
		tt = "STRING"
		ta = "SCALAR"
	}
	if ($5 == "s[]") {
		tt = "STRING_ARRAY"
		ta = "ARRAY"
	}
	if ($5 == "s{}") {
		tt = "I18NSTRING"
		ta = "SCALAR"
	} 
	if ($5 == "x") {
		tt = "BIN"
		ta = "SCALAR"
	}
	if ($6 == "extension") {
		ext = "1"
	}
	if ($2 == "=") {
		tnarg = $1
	} else {
		tnarg = $2
	}
	tn = substr(tnarg, index(tnarg, "_") + 1)
	sn = (substr(tn, 1, 1) tolower(substr(tn, 2)))
	if ($2 == "=") {
		printf("    { \"%s\", \"%s\", %s, RPM_%s_TYPE, RPM_%s_RETURN_TYPE, %d },\n", tnarg, sn, tnarg, tt, ta, ext)
	} else {
		printf("    { \"%s\", \"%s\", %s, RPM_%s_TYPE, RPM_%s_RETURN_TYPE, %d },\n", tnarg, sn, $3, tt, ta, ext)
	}
}' < $1 | sort

cat << EOF
    { NULL, NULL, RPMTAG_NOT_FOUND, RPM_NULL_TYPE, 0 }
};
EOF

