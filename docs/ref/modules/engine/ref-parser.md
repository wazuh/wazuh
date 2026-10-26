
>[!NOTE]
> - The parsers always take a string as input and return a value of a specific type.
> - The parsers are case-sensitive (Unless otherwise specified).
> - Check how parsers are used in the [parsers section](README.md#parse)
> - A field expression must target a field of the schema or a temporary field whose first path segment starts with
>   `_` (for example `_output_field`); any other name makes the asset fail to build. `~` parses without storing.
>   That is why the examples below store into `_`-prefixed fields.
> - A schema field always uses the parser of its schema type, and every argument after its name goes to that parser
>   (`<event.start/RFC3339>`). A temporary field uses `text` unless its first argument names another parser
>   (`<_tmp/long>`); the remaining arguments go to that parser.
> - A parser expression must consume the whole input: anything left after the last token makes the parse fail.

# Schema parser reference

## Boolean parser

The `bool` parser accurately identifies and converts the string representations of `true` and `false` into JSON boolean
types. It is case-insensitive. This parser does not require an end token and is automatically used for fields designated
as `boolean` in the schema.

### Behavior

- The Boolean parser strictly matches "true" or "false" without alternative representations like "yes"/"no" or
  "on"/"off". It accepts no parameters: any argument makes the asset fail to build.
- Is case-insensitive (`TRUE`, `False`, ...).
- The parser does not require an end token.

### Signature

```yaml
<field/bool>
```

### Examples


**Parser configuration**

For the following examples, the parser configuration is as follows:

```yaml
parse|input_field:
  - <_output_field/bool>
```

**Example 1**

Event input
```json
{
  "input_field": "true"
}
```

Output after parse
```json
{
  "input_field": "true",
  "_output_field": true
}
```

**Example 2**

Event input
```json
{
  "input_field": "False"
}
```

Output after parse
```json
{
  "input_field": "False",
  "_output_field": false
}
```

**Example 3**

Event input
```json
{
  "input_field": "Not a boolean"
}
```

Failed parsing, the input is not a valid boolean.

**Example 4**

Event input
```json
{
  "input_field": "1"
}
```

Failed parsing, the input is not a valid boolean.

**Example 5**

Event input
```json
{
  "input_field": "FALSE"
}
```

Output after parse
```json
{
  "input_field": "FALSE",
  "_output_field": false
}
```

## Long parser

The `long` parser is designed to convert strings into 64-bit signed integers, adhering to the format and range typical
of a long data type in most programming environments. This parser ensures the input string represents a number within
the bounds of -2^63 to 2^63-1. Automatically engaged for schema fields defined as type long.

### Behavior

- Accepts strings that represent integer values, including those prefixed with a '-' sign to denote negative numbers.
  A leading '+' and scientific notation are not accepted.
- This parser can process numbers with decimal points but discards any fractional part (truncation toward zero:
  `-1.9` gives `-1`).
- Values outside the 64-bit range fail.
- Accepts no parameters.
- It does not require a specific end token

### Signature

```yaml
<field/long>
```

### Examples

**Parser configuration**

For the following examples, the parser configuration is as follows:
```yaml
parse|input_field:
  - <_output_field/long>
```

**Example 1**

Event input
```json
{
  "input_field": "123"
}
```

Output after parse
```json
{
  "input_field": "123",
  "_output_field": 123
}
```

**Example 2**

Event input
```json
{
  "input_field": "-123"
}
```

Output after parse
```json
{
  "input_field": "-123",
  "_output_field": -123
}
```

**Example 3**

Event input
```json
{
  "input_field": "123.456"
}
```

Output after parse
```json
{
  "input_field": "123.456",
  "_output_field": 123
}
```

Success, the fractional part is discarded.

**Example 4**

Event input
```json
{
  "input_field": "Not a number"
}
```

Failed parsing, the input is not a valid long.

**Example 5**

Event input
```json
{
  "input_field": "1.23"
}
```

Output after parse
```json
{
  "input_field": "1.23",
  "_output_field": 1
}
```

## Double parser

The `double` parser processes strings representing double-precision floating-point values,
adhering to the `IEEE 754` standard. It handles a broad range of numeric formats, including
integers, decimals, and numbers in scientific notation. Automatically used for schema fields defined as type `double`.

### Behavior

- Accepts numbers with optional leading '-' signs to indicate negative values.
- Supports numbers with or without a decimal point, and can interpret numbers in scientific notation (e.g., `1.23E+10`).
- Accepts no parameters.
- It does not require a specific end token

### Signature

```yaml
<field/double>
```

### Examples

**Parser configuration**

For the following examples, the parser configuration is as follows:
```yaml
parse|input_field:
  - <_output_field/double>
```

**Example 1**

Event input
```json
{
  "input_field": "123"
}
```

Output after parse
```json
{
  "input_field": "123",
  "_output_field": 123.0
}
```

**Example 2**

Event input
```json
{
  "input_field": "-123"
}
```

Output after parse
```json
{
  "input_field": "-123",
  "_output_field": -123.0
}
```

**Example 3**

Event input
```json
{
  "input_field": "2.99792458E8"
}
```

Output after parse
```json
{
  "input_field": "2.99792458E8",
  "_output_field": 299792458.0
}
```

**Example 4**

Event input
```json
{
  "input_field": "Not a number"
}
```

Failed parsing, the input is not a valid double.

**Example 5**

Event input
```json
{
  "input_field": "abc123"
}
```

Failed parsing, the input is not a valid double.

**Example 6**

Event input
```json
{
  "input_field": "1,234"
}
```

Failed parsing, commas are not supported.

**Example 7**

Event input
```json
{
  "input_field": "1.23"
}
```

Output after parse
```json
{
  "input_field": "1.23",
  "_output_field": 1.23
}
```


## Float parser

The `float` parser handles strings that represent single-precision (32-bit IEEE 754) floating-point values.
Automatically used for schema fields defined as type `float`.

### Behavior

- Accepts both integers and decimals, with or without a negative sign, and scientific notation (e.g., 2.5E3).
- The value is stored with single precision, so a decimal that has no exact single-precision representation is
  written rounded to it (for example `0.1` is not written as `0.1`).
- Accepts no parameters.
- Does not require a specific end token.

### Signature

```yaml
<field/float>
```

### Examples

**Parser configuration**

For the following examples, the parser configuration is as follows:
```yaml
parse|input_field:
  - <_output_field/float>
```

**Example 1**

Event input
```json
{
  "input_field": "-2.5E3"
}
```

Output after parse
```json
{
  "input_field": "-2.5E3",
  "_output_field": -2500.0
}
```

**Example 2**

Event input
```json
{
  "input_field": "Not a number"
}
```

Failed parsing, the input is not a valid float.

## Scaled float parser

The `scaled_float` parser handles strings that represent floating-point values, interpreting them without applying the
scaling factor during the initial parsing phase. The value is parsed as a double-precision number. Automatically used
for schema fields defined as type `scaled_float`.

### Behavior

- Accepts both integers and decimals, with or without a negative sign.
- Efficiently processes numbers expressed in scientific notation (e.g., 2.5E3).
- Accepts no parameters.
- Does not require a specific end token.

### Signature

```yaml
<field/scaled_float>
```

### Examples

**Parser configuration**

For the following examples, the parser configuration is as follows:
```yaml
parse|input_field:
  - <_output_field/scaled_float>
```

**Example 1**

Event input
```json
{
  "input_field": "123"
}
```

Output after parse
```json
{
  "input_field": "123",
  "_output_field": 123.0
}
```

**Example 2**

Event input
```json
{
  "input_field": "-123"
}
```

Output after parse
```json
{
  "input_field": "-123",
  "_output_field": -123.0
}
```

**Example 3**

Event input
```json
{
  "input_field": "2.5E3"
}
```

Output after parse
```json
{
  "input_field": "2.5E3",
  "_output_field": 2500.0
}
```

**Example 4**

Event input
```json
{
  "input_field": "Not a number"
}
```

Failed parsing, the input is not a valid scaled float.

**Example 5**

Event input
```json
{
  "input_field": "1.0E-2"
}
```

Output after parse
```json
{
  "input_field": "1.0E-2",
  "_output_field": 0.01
}
```

## Half Float parser

The `half_float` parser handles strings that represent half-precision floating-point values. Automatically used for
schema fields defined as type `half_float`.

### Behavior

- Accepts both integers and decimals, with or without a negative sign.
- Efficiently processes numbers expressed in scientific notation (e.g., 2.5E3).
- Rejects values outside the half-precision range, -65504 to 65504.
- The value is parsed and stored with single precision (it is not rounded to half precision).
- Accepts no parameters.
- Does not require a specific end token.

### Signature

```yaml
<field/half_float>
```

### Examples

**Parser configuration**

For the following examples, the parser configuration is as follows:
```yaml
parse|input_field:
  - <_output_field/half_float>
```

**Example 1**

Event input
```json
{
  "input_field": "123"
}
```

Output after parse
```json
{
  "input_field": "123",
  "_output_field": 123.0
}
```

**Example 2**

Event input
```json
{
  "input_field": "-123"
}
```

Output after parse
```json
{
  "input_field": "-123",
  "_output_field": -123.0
}
```

**Example 3**

Event input
```json
{
  "input_field": "2.5E3"
}
```

Output after parse
```json
{
  "input_field": "2.5E3",
  "_output_field": 2500.0
}
```

**Example 4**

Event input
```json
{
  "input_field": "Not a number"
}
```

Failed parsing, the input is not a valid half float.

**Example 5**

Event input
```json
{
  "input_field": "5.0E-1"
}
```

Output after parse
```json
{
  "input_field": "5.0E-1",
  "_output_field": 0.5
}
```

**Example 6**

Event input
```json
{
  "input_field": "65505"
}
```

Failed parsing, the input is out of the half-float range.

## Byte parser

The `byte` parser interprets strings as 8-bit signed integers, handling values from -128 to 127. This parser is crucial
for processing data that fits within a compact numerical range, such as status codes or small counters.
Automatically used for schema fields defined as type `byte`.

### Behavior

- Strictly limits the accepted values to the defined byte range, rejecting inputs outside -128 to 127.
- Does not require a specific end token.
- Accepts numeric strings that may optionally include a '-' sign to indicate negative values.
- This parser can process numbers with decimal points but discards any fractional part (truncation toward zero).
- Accepts no parameters.

### Signature

```yaml
<field/byte>
```

### Examples

**Parser configuration**

For the following examples, the parser configuration is as follows:
```yaml
parse|input_field:
  - <_status_code/byte>
```

**Example 1**

Event input
```json
{
  "input_field": "123"
}
```

Output after parse
```json
{
  "input_field": "123",
  "_status_code": 123
}
```

**Example 2**

Event input
```json
{
  "input_field": "-123"
}
```

Output after parse
```json
{
  "input_field": "-123",
  "_status_code": -123
}
```

**Example 3**

Event input
```json
{
  "input_field": "128"
}
```

Failed parsing, the input is not a valid byte (out of range).

**Example 4**

Event input
```json
{
  "input_field": "Not a number"
}
```

Failed parsing, the input is not a valid byte.

## Integer parser

The `integer` parser interprets strings as 32-bit signed integers, handling values from -2,147,483,648 to 2,147,483,647.
This parser is essential for processing standard integer values commonly used in various applications.
Automatically used for schema fields defined as type `integer`.

### Behavior

- Strictly limits the accepted values to the defined integer range, rejecting inputs outside -2^31 to 2^31-1.
- Does not require a specific end token.
- Accepts numeric strings that may optionally include a '-' sign to indicate negative values.
- This parser can process numbers with decimal points but discards any fractional part (truncation toward zero).
- Accepts no parameters.

### Signature

```yaml
<field/integer>
```

### Examples

**Parser configuration**

For the following examples, the parser configuration is as follows:
```yaml
parse|input_field:
  - <_status_code/integer>
```

**Example 1**

Event input
```json
{
  "input_field": "123"
}
```

Output after parse
```json
{
  "input_field": "123",
  "_status_code": 123
}
```

**Example 2**

Event input
```json
{
  "input_field": "-123"
}
```

Output after parse
```json
{
  "input_field": "-123",
  "_status_code": -123
}
```

**Example 3**

Event input
```json
{
  "input_field": "2147483648"
}
```

Failed parsing, the input is not a valid integer (out of range).

**Example 4**

Event input
```json
{
  "input_field": "Not a number"
}
```

Failed parsing, the input is not a valid integer.

**Example 5**

Event input
```json
{
  "input_field": "123.456"
}
```

Output after parse
```json
{
  "input_field": "123.456",
  "_status_code": 123
}
```

Success, the fractional part is discarded.

## Short parser

The `short` parser interprets strings as 16-bit signed integers, handling values from -32,768 to 32,767.
This parser is useful for processing data that fits within a moderate numerical range.
Automatically used for schema fields defined as type `short`.

### Behavior

- Strictly limits the accepted values to the defined short range, rejecting inputs outside -2^15 to 2^15-1.
- Does not require a specific end token.
- Accepts numeric strings that may optionally include a '-' sign to indicate negative values.
- This parser can process numbers with decimal points but discards any fractional part (truncation toward zero).
- Accepts no parameters.

### Signature

```yaml
<field/short>
```

### Examples

**Parser configuration**

For the following examples, the parser configuration is as follows:
```yaml
parse|input_field:
  - <_status_code/short>
```

**Example 1**

Event input
```json
{
  "input_field": "123"
}
```

Output after parse
```json
{
  "input_field": "123",
  "_status_code": 123
}
```

**Example 2**

Event input
```json
{
  "input_field": "-123"
}
```

Output after parse
```json
{
  "input_field": "-123",
  "_status_code": -123
}
```

**Example 3**

Event input
```json
{
  "input_field": "32768"
}
```

Failed parsing, the input is not a valid short (out of range).

**Example 4**

Event input
```json
{
  "input_field": "Not a number"
}
```

Failed parsing, the input is not a valid short.

**Example 5**

Event input
```json
{
  "input_field": "123.456"
}
```

Output after parse
```json
{
  "input_field": "123.456",
  "_status_code": 123
}
```

Success, the fractional part is discarded.

## Unsigned long parser

The `unsigned_long` parser interprets strings as 64-bit unsigned integers, handling values from 0 to 18,446,744,073,709,551,615 (2^64-1).
This parser is essential for processing large positive integer values, such as counters, IDs, or timestamps.
Automatically used for schema fields defined as type `unsigned_long` or `token_count`.

### Behavior

- Strictly limits the accepted values to the defined unsigned long range, rejecting inputs outside 0 to 2^64-1.
- Does not require a specific end token.
- Accepts only non-negative numeric strings (no '-' sign allowed).
- This parser can process numbers with decimal points but discards any fractional part (truncation toward zero).
- Accepts no parameters.

### Signature

```yaml
<field/unsigned_long>
```

### Examples

**Parser configuration**

For the following examples, the parser configuration is as follows:
```yaml
parse|input_field:
  - <_status_code/unsigned_long>
```

**Example 1**

Event input
```json
{
  "input_field": "123"
}
```

Output after parse
```json
{
  "input_field": "123",
  "_status_code": 123
}
```

**Example 2**

Event input
```json
{
  "input_field": "-123"
}
```

Failed parsing, the input is not a valid unsigned long (negative values not allowed).

**Example 3**

Event input
```json
{
  "input_field": "18446744073709551616"
}
```

Failed parsing, the input is not a valid unsigned long (out of range).

**Example 4**

Event input
```json
{
  "input_field": "Not a number"
}
```

Failed parsing, the input is not a valid unsigned long.

**Example 5**

Event input
```json
{
  "input_field": "123.456"
}
```

Output after parse
```json
{
  "input_field": "123.456",
  "_status_code": 123
}
```

Success, the fractional part is discarded.

## Text parser

The Text Parser is designed to extract sequences of characters from an input string up until a specified delimiter or
end token is encountered. It is highly effective for parsing unstructured or semi-structured text, making it particularly
useful for extracting fields from logs or similar textual data sources. Automatically used for schema fields defined as type `keyword`, `text`, `wildcard`,
`match_only_text`, `completion`, `search_as_you_type`, `constant_keyword` and `semantic`.

### Behavior

- Captures all characters in the input string until it reaches a designated end token.
- Requires an end token: it must be followed by a literal or be the last token of the expression, where it consumes
  all characters up to the end of the input string. Directly followed by another field, the asset fails to build.
- Fails when it would capture nothing (the end token is found at once or the input is empty).
- Accepts no parameters.
- Is the default parser of a temporary field that names no parser (`<_field>`).

### Signature

```yaml
<field/text>
```

### Examples: With prefix

**Parser configuration**

For the following examples, the parser configuration is as follows:
```yaml
parse|event.original:
 - "Prefix: <_output_field/text>"
```

**Example 1**

Event input
```json
{
  "event.original": "Prefix: This is a test"
}
```

Output after parse
```json
{
  "event.original": "Prefix: This is a test",
  "_output_field": "This is a test"
}
```

**Example 2**

Event input
```json
{
  "event.original": "Prefix: "
}
```

Failed parsing, no text to parse.

**Example 3**

Event input
```json
{
  "event.original": "Some text"
}
```

Failed parsing, no prefix to match.


### Examples 2: With Prefix and suffix

**Parser configuration**

For the following examples, the parser configuration is as follows:
```yaml
parse|event.original:
 - "Prefix: <_output_field/text> Suffix"
```

**Example 1**

Event input
```json
{
  "event.original": "Prefix: This is a test Suffix"
}
```

Output after parse
```json
{
  "event.original": "Prefix: This is a test Suffix",
  "_output_field": "This is a test"
}
```

**Example 2**

Event input
```json
{
  "event.original": "Prefix: - Suffix"
}
```

Output after parse
```json
{
  "event.original": "Prefix: - Suffix",
  "_output_field": "-"
}
```

**Example 3**

Event input
```json
{
  "event.original": "Prefix: Suffix"
}
```

Failed parsing, no text to parse.

**Example 4**

Event input
```json
{
  "event.original": "Some text"
}
```

Failed parsing, no prefix to match.

## IP parser

The `ip` parser is designed to extract and validate IP addresses from input strings. It can handle both IPv4 and IPv6
addresses, ensuring that the extracted values conform to the expected format. Automatically used for schema fields defined
as type `ip`.

### Behavior

- Extracts and validates IP addresses in both IPv4 and IPv6 formats (validated with `inet_pton`); the address is
  stored as written.
- Accepts no parameters.
- Does not require a specific end token.

### Signature

```yaml
<field/ip>
```

### Examples

**Parser configuration**

For the following examples, the parser configuration is as follows:
```yaml
parse|input_field:
  - <_output_field/ip>
```

**Example 1**

Input event
```json
{
  "input_field": "192.168.1.1"
}
```

Output after parse
```json
{
  "input_field": "192.168.1.1",
  "_output_field": "192.168.1.1"
}
```

**Example 2**

Input event
```json
{
  "input_field": "2001:0db8:85a3:0000:0000:8a2e:0370:7334"
}
```

Output after parse
```json
{
  "input_field": "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
  "_output_field": "2001:0db8:85a3:0000:0000:8a2e:0370:7334"
}
```

**Example 3**

Input event
```json
{
  "input_field": "Not an IP address"
}
```

Failed parsing, the input is not a valid IP address.

## Date parser

The `date` parser is essential for transforming date strings into a standardized `ISO 8601` UTC format with
millisecond precision (`YYYY-MM-DDTHH:MM:SS.sssZ`). It supports a wide array of date formats, both custom and
predefined, and locale-aware parsing. Automatically applied to schema fields defined as type `date` or `date_nanos`.

### Behavior

- Format Matching: Attempts to match the input date string against the specified format.
- Missing year: when the format has no year, the current year is used.
- Time zone: a numeric offset (`%z`, `%Ez`) is applied to convert the time to UTC; a time zone name (`%Z`, for example
  `MST` or `UTC`, looked up in the time zone database) makes the time a local time in that zone, converted to UTC
  (`15:04:05 MST` becomes `22:04:05Z`; a local time in a DST gap or overlap takes the earliest instant). When the
  format carries no time zone information, the time is taken as UTC.
- Standardization: Successfully parsed dates are written as `YYYY-MM-DDTHH:MM:SS.sssZ`.
- Custom Field Applicability: Can be manually applied to temporary fields where specific date parsing is required.
- Does not require a specific end token: it consumes what the format matches.

### Signature

```yaml
<field/date/Format/[Locale]>
```
- `Format`: one of
    - a format string, recognised by containing a `%`;
    - a predefined format name from the table below;
    - a sample date (any other value): the format is the single predefined format that matches the whole sample. A
      sample that matches no predefined format, or more than one, makes the asset fail to build.
- `Locale`: Optional locale name used to parse the date (for example `en_GB.UTF-8`). The default is the C/POSIX
    locale. The locale must be installed on the host, otherwise the asset fails to build.

More than two arguments make the asset fail to build.

***Supported formats***

The parser supports several predefined date formats which are commonly used in various logging standards, such as syslog,
RFCs, and more. Users can specify a custom format using the [syntax from Howard Hinnant's date library](https://howardhinnant.github.io/date/date.html#from_stream_formatting), or choose from
predefined formats like RFC3339, ISO8601, etc.


| Predefined Format      | Equivalent expression | Match example |
|-----------------------|---------------------|-----------------------------------|
| ANSIC                 | %a %b %d %T %Y      | Mon Jan _2 15:04:05 2006          |
| UnixDate              | %a %b %d %T %Z %Y   | Mon Jan _2 15:04:05 MST 2006      |
| RubyDate              | %a %b %d %T %z %Y   | Mon Jan 02 15:04:05 -0700 2006    |
| RFC822                | %d %b %y %R %Z      | 02 Jan 06 15:04 MST               |
| RFC822Z               | %d %b %y %R %z      | 02 Jan 06 15:04 -0000             |
| RFC850                | %A, %d-%b-%y %T %Z  | Monday, 02-Jan-06 15:04:05 MST    |
| RFC1123               | %a, %d %b %Y %T %Z  | Mon, 02 Jan 2006 15:04:05 MST     |
| RFC1123Z              | %a, %d %b %Y %T %z  | Mon, 02 Jan 2006 15:04:05 -0700   |
| RFC3339               | %FT%TZ%Ez           | 2006-01-02T15:04:05Z07:00         |
| RFC3164               | %b %d %R:%6S %Z     | Mar 1 18:48:50.483 UTC            |
| SYSLOG                | %b %d %T            | Jun 14 15:16:01                   |
| ISO8601               | %FT%T%Ez            | 2018-08-14T14:30:02.203151+02:00  |
| ISO8601Z              | %FT%TZ              | 2018-08-14T14:30:02.203151Z       |
| HTTPDATE              | %d/%b/%Y:%T %z      | 26/Dec/2016:16:22:14 +0000        |
| NGINX_ERROR           | %Y/%m/%d %T         | 2019/10/30 23:26:34               |
| POSTGRES              | %F %H:%M:%6S %Z     | 2021-02-14 10:45:33 UTC           |

### Examples: Without locale

**Parser configuration**
For the following examples, the parser configuration is as follows:
```yaml
parse|event_time:
  - <_tmp_time/date/RFC3339>
```

**Example 1**
Event input
```json
{
  "event_time": "2020-01-02T03:04:05Z07:00"
}
```

Output after parse
```json
{
  "event_time": "2020-01-02T03:04:05Z07:00",
  "_tmp_time": "2020-01-01T20:04:05.000Z"
}
```

**Example 2**

Input event
```json
{
  "event_time": "Not a date"
}
```

Failed parsing, the input is not a valid date.

**Example 3**

Input event
```json
{
  "event_time": "2020-01-02T03:04:05"
}
```

Failed parsing, the input is not a valid date, missing timezone.


### Examples: With locale

**Parser configuration**

For the following examples, the parser configuration is as follows:
```yaml
parse|event_time:
  - <event.start/HTTPDATE/en_GB.UTF-8>
```

> [!NOTE]
> The `date` parser use is implicit, because the parser is automatically applied to schema fields defined as type `date`
> like `event.start`; `HTTPDATE` and `en_GB.UTF-8` are its two arguments. The `en_GB.UTF-8` locale must be installed
> on the host, otherwise the asset fails to build.


**Example 1**

Input event
```json
{
  "event_time": "02/Jan/2020:03:04:05 +0000"
}
```

Output after parse
```json
{
  "event_time": "02/Jan/2020:03:04:05 +0000",
  "event.start": "2020-01-02T03:04:05.000Z"
}
```

**Example 2**

Input event
```json
{
  "event_time": "Not a date"
}
```

Failed parsing, the input is not a valid date.


## Binary parser

The `binary` parser processes and validates base64 encoded strings, ensuring data integrity and compliance with base64
encoding standards. This parser is essential for handling encoded files and data transmissions in a variety of digital
communication contexts. Automatically used for schema fields defined as type `binary`.

### Behavior

- Validates base64 encoded strings: it consumes characters from A-Z, a-z, 0-9, '+' and '/', then up to two '='
  padding characters, and fails unless the consumed length is a multiple of 4.
- The value is stored as written (still base64 encoded); it is not decoded.
- Accepts no parameters.
- Does not require a specific end token.

### Signature

```yaml
<field/binary>
```

### Example

**Parser configuration**

For the following examples, the parser configuration is as follows:
```yaml
parse|input_field:
  - <_output_field/binary>
```

**Example 1**

Event input
```json
{
  "input_field": "SGVsbG8sIFdvcmxkIQ=="
}
```

Output after parse
```json
{
  "input_field": "SGVsbG8sIFdvcmxkIQ==",
  "_output_field": "SGVsbG8sIFdvcmxkIQ=="
}
```

**Example 2**

Input event
```json
{
  "input_field": "Not a base64 string"
}
```

Failed parsing, the input is not a valid base64 string.

**Example 3**

Input event
```json
{
  "input_field": "SGVsbG8sIFdvcmxkIQ"
}
```

Failed parsing, the input is not a valid base64 string, missing padding.

**Example 4**

Input event

```json
{
  "input_field": "SGVsbG8sIFdvcmxkIQ@="
}
```

Failed parsing, the input is not a valid base64 string, invalid character.

---

# High level parser reference

## Literal

The Literal Parser specializes in matching specific, fixed sequences of characters within the input text. It plays a
crucial role in constructing parser expressions by ensuring accurate identification of static text elements within log
entries. Utilized primarily to confirm the presence of predetermined text in the data stream, the Literal Parser operates
either explicitly or implicitly within parser expressions. 

### Behavior

- Matches the exact sequence of characters specified in the parser expression; the match is case-sensitive.
- Does not require an end token.
- Has 2 modes of syntax: explicit and implicit.
- In an implicit literal, `<`, `?`, `(`, `)` and `\` are reserved and must be escaped with `\`. In an argument
  (explicit form, and every parser argument), `/`, `>` and `\` must be escaped with `\`.
- The explicit form takes exactly one argument, the literal; the stored value is the literal itself.

### Signature

**Explicit Usage with Storage**:
Less common, this method involves declaring the literal text along with a destination field for storage, useful in
scenarios where the matched text forms a part of the resultant data

```yaml
<_tmp_lit/literal/literal string><source.ip>
```

- `literal string`: The literal text to match

**Implicit Usage**:
More common, this method involves declaring the literal text without a destination field, useful when the matched text
serves as a condition or trigger for subsequent parsing operations

```yaml
deny from <source.ip>
```

>[!NOTE]
> Both forms are used to parse logs like `deny from 66.249.66.167` to extract and store the IP address in source.ip.

### Example without explicit storage (Common case)

**Parser configuration**

```yaml
parse|event.original:
  - deny from <source.ip>
```

**Input event**

```json
{
  "event.original": "deny from 1.1.1.1"
}
```

**Output after parse**

```json
{
  "event.original": "deny from 1.1.1.1",
  "source.ip": "1.1.1.1"
}
```

### Example with explicit storage

**Parser configuration**

```yaml
parse|event.original:
  - <_tmp_lit/literal/deny from ><source.ip>
```

**Input event**

```json
{
  "event.original": "deny from 1.1.1.1"
}
```

**Output after parse**

```json
{
  "event.original": "deny from 1.1.1.1",
  "source.ip": "1.1.1.1",
  "_tmp_lit": "deny from "
}
```

## Quoted

The `quoted` parser is designed to extract sequences of characters that are enclosed by a specified delimiter, often used to handle quoted strings within text. This parser allows the specification of both the delimiter and the escape character, facilitating the accurate parsing of string data that may include escaped quotes.

### Behavior

- The input must start with the delimiter; the parser consumes up to the first unescaped delimiter and stores the
  content between both delimiters. There is no nesting.
- Inside the string, the escape character may only precede the delimiter or another escape character; any other
  character after it makes the parse fail. Every escape character is removed from the stored value.
- By default, the parser uses a double quotation mark (`"`) as the delimiter and a backslash (`\`) as the escape character, but both can be customized to fit different data formats
- Each argument must be a single character, and the delimiter and the escape character must differ; at most two
  arguments are accepted. Otherwise the asset fails to build.
- No specific end token is required

### Signature

```yaml
<field/quoted/[delim_char]/[esc_char]>
```

- `delim_char`: The character used to denote the beginning and end of the quoted string. The default is the double
    quotation mark (").
- `esc_char`: The character used to escape the delimiter within the string, allowing the delimiter to be used as part of
    the string content. The default is the backslash (`\`).

### Examples with default delimiter and escape character

**Parser configuration**

For the following examples, the parser configuration is as follows:
```yaml
parse|event.original:
  - "msg=<_temp_quoted/quoted>"
```

**Example 1**

Input event
```json
{
  "event.original": "msg=\"This is a quoted string\""
}
```

Output after parse
```json
{
  "event.original": "msg=\"This is a quoted string\"",
  "_temp_quoted": "This is a quoted string"
}
```

### Examples with custom delimiter and escape character

**Parser configuration**

For the following examples, the parser configuration is as follows:
```yaml
parse|event.original:
  - "msg=<_temp_quoted/quoted/'/\\\\>"
```

The escape character `\` is itself the argument escape of a parser expression, so it is written `\\` in the
expression, and each of those backslashes is doubled again inside a double-quoted YAML string.

**Example 1**

Input event
```json
{
  "event.original": "msg='This is a quoted string'"
}
```

Output after parse
```json
{
  "event.original": "msg='This is a quoted string'",
  "_temp_quoted": "This is a quoted string"
}
```

**Example 2**

Input event
```json
{
  "event.original": "msg='It\\'s escaped'"
}
```

Output after parse
```json
{
  "event.original": "msg='It\\'s escaped'",
  "_temp_quoted": "It's escaped"
}
```

## DSV

The `dsv` (Delimiter-Separated Values) Parser is engineered to parse structured text data where elements are separated
by a specific delimiter, such as commas, tabs, or other characters. This parser is adept at managing complex data formats
that include quoted sections and escape characters, making it essential for accurately extracting fields from inputs like
CSV files or similar structured data streams.

### Behavior

- The parser splits the input based on the specified delimiter while respecting quoted sections and recognizing
    escape characters.
- Supports a wide range of delimiter characters, including commas, tabs, and custom characters.
- Ensures all expected elements are present; fails if the count of extracted values does not match the expected number.
- Values are stored as strings, an empty value as `null`; a `.` in an output name nests the value (`a.b` stores
  `{"a":{"b":...}}`).
- Requires an end token to determine the boundary of parsing. If positioned at the end of a parser expression, the end of the string acts as the end token.
- Output names are JSON Pointer tokens: `~0` and `~1` are the only valid escapes after `~`; a name with any other
    escape is rejected when the asset is built.
- The delimiter, quote and escape arguments must be single characters, and at least two output names are required;
  otherwise the asset fails to build.
- Common Errors:
    - Unbalanced Quotes: Fails parsing if quotes enclosing fields are not properly closed, as it cannot accurately determine the boundaries of the quoted text.
    - Insufficient Values: Fails if the number of fields extracted is less than expected; no data is stored.
    - Extra Values: Fails if text is left after the last expected field.

### Signature

```yaml
<field/dsv/delim_char/quote_char/esc_char/out1/out2/...>
```

- `delim_char`: The character used to separate individual elements within the input string.
- `quote_char`: The character used to enclose elements, allowing delimiters within the quoted text to be ignored as
    separators.
- `esc_char`: The character used to escape the quote character within quoted elements, facilitating the inclusion of
    quote characters as part of the field data.
- `out[i]`: The specific field names within the output object where the parsed values will be stored. This argument is
    variadic, allowing multiple fields to be defined for extraction. Each field corresponds to a column in the DSV data.


### Examples: Simple Delimited Data Extraction

**Parser configuration**

For the following examples, the parser configuration is as follows:
```yaml
parse|input:
- <_outField/dsv/|/'/'/out1/out2/out3/outN>
```

**Example 1**

Input event
```json
{
  "input": "value1|value2|value3|valueN"
}
```

Output after parse
```json
{
  "input": "value1|value2|value3|valueN",
  "_outField": {
    "out1": "value1",
    "out2": "value2",
    "out3": "value3",
    "outN": "valueN"
  }
}
```

### Examples: Quoted and Escaped Values

**Parser configuration**

For the following examples, the parser configuration is as follows:
```yaml
parse|input:
- <_outField/dsv/|/'/'/out1/out2/out3>
```

**Example 1**

Input event
```json
{
  "input": "value1|value2"
}
```

The parser does not match because the input does not contain the expected number of fields.

**Example 2**
Input event
```json
{
  "input": "'value-|-1'|'value-''-2'|'value-|''-3'"
}
```

Output after parse
```json
{
  "input": "'value-|-1'|'value-''-2'|'value-|''-3'",
  "_outField": {
    "out1": "value-|-1",
    "out2": "value-'-2",
    "out3": "value-|'-3"
  }
}
```

## CSV

The `csv` parser is a specialized version of the `dsv` parser tailored to handle Comma-Separated Values (CSV) data
formats. It is designed to parse structured text data where elements are separated by commas, with support for quoted
sections and escape characters. The `csv` parser is essential for accurately extracting fields from CSV files or similar
structured data streams.

### Behavior

- The parser splits the input string by commas, treating sections within quotes as single fields regardless of internal commas.
- Fields may be enclosed in double quotes (`"`); a double quote inside a quoted field is written doubled (`""`).
- Checks for balanced quotes and the correct number of fields as expected.
- Values are stored as strings, an empty value as `null`, as in `dsv`.
- At least two output names are required; otherwise the asset fails to build.
- Fails if quotes are unbalanced, fields are missing, or formatting errors occur.
- Requires an end token to determine the boundary of parsing. If positioned at the end of a parser expression, the end of
    the string acts as the end token.
- Output names are JSON Pointer tokens: `~0` and `~1` are the only valid escapes after `~`; a name with any other
    escape is rejected when the asset is built.


### Signature

```yaml
<field/csv/out1/out2/...>
```

- `out[i]`: The specific field names within the output object where the parsed values will be stored. This argument is
    variadic, allowing multiple fields to be defined for extraction. Each field corresponds to a column in the CSV data.

### Examples

**Parser configuration**

For the following examples, the parser configuration is as follows:
```yaml
parse|input:
- <_outField/csv/out1/out2/out3>
```

**Example 1**

Input event
```json
{
  "input": "value1,value2,value3"
}
```

Output after parse
```json
{
  "input": "value1,value2,value3",
  "_outField": {
    "out1": "value1",
    "out2": "value2",
    "out3": "value3"
  }
}
```

**Example 2**

Input event
```json
{
  "input": "value1,\"value,2\",value3"
}
```

Output after parse
```json
{
  "input": "value1,\"value,2\",value3",
  "_outField": {
    "out1": "value1",
    "out2": "value,2",
    "out3": "value3"
  }
}
```

**Example 3**

Input event
```json
{
  "input": "value1,\"value\"\"2\",value3"
}
```

Input in string format: `value1,"value""2",value3`

Output after parse
```json
{
  "input": "value1,\"value\"\"2\",value3",
  "_outField": {
    "out1": "value1",
    "out2": "value\"2",
    "out3": "value3"
  }
}
```

**Example 4**

Input event
```json
{
  "input": "value1,value2"
}
```

The parser does not match because the input does not contain the expected number of fields.


## Parse JSON

The `json` parser is designed to extract and parse JSON values embedded within input strings. This parser is
essential for handling structured data formats that include JSON data within text fields, allowing for the extraction of
specific fields from complex JSON structures. This parser is capable of parsing any JSON type, including objects, arrays,
strings, numbers, and booleans.

### Behavior

- Parses one JSON value at the start of the input and stops where that value ends.
- Supports nested JSON structures up to the nesting limit below.
- Accepts no parameters.
- Input nested deeper than 256 levels (json::Json::MAX_DEPTH) is rejected: the parser fails as on invalid input, the field is not set and nothing is logged; the nesting depth exceeds the limit (256) message names the cap in test traces.
  The root container is level 1: 256 nested containers (objects and arrays) parse, the 257th fails. The limit is
  fixed (not configurable) and is not an input-size limit; the event size is capped by remoted.
- No end token is required.

### Signature

```yaml
<field/json>
```

### Examples

**Parser configuration**

For the following examples, the parser configuration is as follows:
```yaml
parse|input:
- <_outField/json>
```

**Example 1**

Input event
```json
{
  "input": "{\"field1\": \"value1\", \"field2\": 123, \"field3\": [\"a\", \"b\", \"c\"]}"
}
```

Output after parse
```json
{
  "input": "{\"field1\": \"value1\", \"field2\": 123, \"field3\": [\"a\", \"b\", \"c\"]}",
  "_outField": {
    "field1": "value1",
    "field2": 123,
    "field3": ["a", "b", "c"]
  }
}
```

**Example 2**

Input event
```json
{
  "input": "{\"field1\": {\"nested1\": \"value1\", \"nested2\": 123}}"
}
```

Output after parse
```json
{
  "input": "{\"field1\": {\"nested1\": \"value1\", \"nested2\": 123}}",
  "_outField": {
    "field1": {
      "nested1": "value1",
      "nested2": 123
    }
  }
}
```


**Example 3**

Input event
```json
{
  "input": "123.45"
}

```

Output after parse
```json
{
  "input": "123.45",
  "_outField": 123.45
}
```

## Parse XML

The `xml` Parser transforms XML-formatted data into a structured JSON format, supporting two distinct modes for
versatility: the `Default Mode` for general XML structures and the `Windows Mode`, specifically designed for parsing
Windows event logs which often contain complex and repetitive tag structures.

### Behavior

- Extracts and parses XML objects embedded within input strings.
- Depending on the selected mode, it converts XML nodes to JSON objects, preserving the original hierarchy and
  attributes.
- XML attributes are prefixed with '@' and integrated into their respective JSON objects.
- Text and CDATA content of an XML element is identified with a '#text' key in the JSON output. If no text or CDATA is
  present, the key is ignored. A CDATA section is a leaf: it does not create a member of its own (for example,
  `<a><![CDATA[x]]></a>` produces `{"a":{"#text":"x"}}`).
- Repeated sibling elements with the same name become an array.
- In `windows` mode only: the root `Event` element (and its attributes) is omitted, and each `Data` element with a
  `Name` attribute is stored as a string member named after that attribute, instead of a `Data` object.
- Input nested deeper than 256 levels (json::Json::MAX_DEPTH) is rejected: the parser fails as on invalid input, the field is not set and nothing is logged; the nesting depth exceeds the limit (256) message names the cap in test traces.
  Depth is counted in nested XML elements: 256 nested elements parse, the 257th fails; text and CDATA are leaves
  (`#text`) and add no level. In `windows` mode the root `Event`, although omitted from the output, is level 1. The
  limit is fixed (not configurable) and is not an input-size limit; the event size is capped by remoted.
- End token is required: the parser takes the text up to the next literal, or to the end of the input when it is the
  last token, and fails if that text is not well-formed XML.

### Signature

```yaml
<field/xml/[mode]>
```

- `mode`: Optional parameter specifying the parser mode, `default` or `windows`; any other value, or more than one
  argument, makes the asset fail to build. If omitted, the default mode is used. For Windows Event Logs,
  use `windows` mode. This mode processes complex XML structures by ignoring repetitive tags like `<Event>` and uses the
  unique identifiers from `<Data>` tags directly as keys in the resulting JSON object.

### Examples of Default Mode

**Parser configuration**

For the following examples, the parser configuration is as follows:
```yaml
parse|input:
- <_outField/xml>
```

**Example 1**

Input event
```json
{
  "input": "<SomeField>Some data</SomeField>"
}
```

Output after parse
```json
{
  "input": "<SomeField>Some data</SomeField>",
  "_outField": {
    "SomeField": {
      "#text": "Some data"
    }
  }
}
```

**Example 2**

Input event
```json
{
  "input": "<SomeField attr1=\"value1\" attr2=\"value2\">Some data</SomeField>"
}
```

Output after parse
```json
{
  "input": "<SomeField attr1=\"value1\" attr2=\"value2\">Some data</SomeField>",
  "_outField": {
    "SomeField": {
      "#text": "Some data",
      "@attr1": "value1",
      "@attr2": "value2"
    }
  }
}
```

**Example 3**

Input event
```json
{
  "input": "<SomeField attr='attr value'><SubField>Some data</SubField></SomeField>"
}
```

Output after parse
```json
{
  "input": "<SomeField attr='attr value'><SubField>Some data</SubField></SomeField>",
  "_outField": {
    "SomeField": {
      "@attr": "attr value",
      "SubField": {
        "#text": "Some data"
      }
    }
  }
}
```

**Example 4**

Input event
```json
{
  "input": "<SomeField attr=\"attr value\" val=\"10071992\"/>"
}
```

Output after parse
```json
{
  "input": "<SomeField attr=\"attr value\" val=\"10071992\"/>",
  "_outField": {
    "SomeField": {
      "@attr": "attr value",
      "@val": "10071992"
    }
  }
}
```


### Examples of Windows Mode


**Parser configuration**

For the following examples, the parser configuration is as follows:
```yaml
parse|input:
- <_outField/xml/windows>
```

**Example 1**

Input event
```json
{
  "input": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><EventID>5379</EventID></System><EventData><Data Name='SubjectUserName'>vagrant</Data><Data Name='ClientProcessId'>5572</Data></EventData></Event>"
}
```

For the purpose of this example, the well-formatted XML is shown below:

```xml
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
  <System>
    <EventID>5379</EventID>
  </System>
  <EventData>
    <Data Name='SubjectUserName'>vagrant</Data>
    <Data Name='ClientProcessId'>5572</Data>
  </EventData>
</Event>
```

Output after parse
```json
{
  "input": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><EventID>5379</EventID></System><EventData><Data Name='SubjectUserName'>vagrant</Data><Data Name='ClientProcessId'>5572</Data></EventData></Event>",
  "_outField": {
    "System": {
      "EventID": {
        "#text": "5379"
      }
    },
    "EventData": {
      "ClientProcessId": "5572",
      "SubjectUserName": "vagrant"
    }
  }
}

```

>[!NOTE]
> Note that the root `Event` object is ignored, and the `Data` elements are directly mapped using their `Name`
> attributes as keys in the resulting JSON object.

## KV

The `kv` (Key-Value) Parser is specifically designed to parse strings that encode data as key-value pairs. This parser
effectively extracts pairs using customizable delimiters and separators, handling complex data formats that may include
nested delimiters or escape sequences.

### Behavior

- Extracts key-value pairs from input strings based on specified delimiter and separator.
  - Keys are linked to values by the `separator` token (may be multi‑character).
  - Each key-value pair is split from others, given the `delimiter` token (may be multi‑character).
  - All the characters contained between the `quote` characters will be considered part of a single value,
    even the `separator` and `delimiter` tokens
- Customizable delimiters and separator tokens. Exactly four arguments are required: the separator and the delimiter
  must be non-empty and different, the quote and the escape must be single characters; otherwise the asset fails to
  build.
- Values are stored as strings with the outer quotes removed; a key with an empty value is stored as `null`.
- Input nested deeper than 256 levels (json::Json::MAX_DEPTH) is rejected: the parser fails as on invalid input, the field is not set and nothing is logged; the nesting depth exceeds the limit (256) message names the cap in test traces.
  For every key, with or without a value, each `.` in the key creates one nested level in the output (`a.b=` maps to
  `{"a":{"b":null}}`), so the destination path has one level per `.` plus one and the limit counts those levels: a key
  with 255 dots is mapped, a key with 256 dots fails. The limit is fixed (not configurable) and is not an input-size limit; the event size is capped by remoted.
- Keys are written as JSON Pointer tokens: `~0` and `~1` are the pointer escapes (`a~1b=v` maps to the member `a/b`).
  A `~` followed by any other character, or at the end of the key, is not a valid pointer: the parser fails as on
  invalid input and the field is not set.
- It does not require an end token.

### Signature

```yaml
<field/kv/sep_token/delim_token/quote_char/esc_char>
```

- `sep_token`: Token that separates keys from their corresponding values.
- `delim_token`: Token that delimits one key-value pair from another.
- `quote_char`: Character used for quoting complex values that may contain delimiters or separators as literal content.
- `esc_char`: Character used to escape the quote character, the separator or the delimiter within values, allowing
  them to be included as part of the data. When `esc_char` is the backslash it is written `\\` (see
  [Literal](#literal)). When it equals `quote_char`, a doubled quote inside a quoted value stands for one quote.

### Examples: Simple Key-Value Pair Extraction

**Parser configuration**

```yaml
parse|input:
- <_outField/kv/=/,/'/'>
```

Input event
```json
{
  "input": "key1=value1,key2=value 2,key3='value 3'"
}
```

Output after parse
```json
{
  "input": "key1=value1,key2=value 2,key3='value 3'",
  "_outField": {
    "key1": "value1",
    "key2": "value 2",
    "key3": "value 3"
  }
}
```


### Examples: Key-Value Pair Extraction with Escaped Characters

**Parser configuration**

```yaml
parse|input:
- <_outField/kv/=/,/'/\\>
```

Input event
```json
{
  "input": "key1=value1,key2=value\\,2,key3='value ,3'"
}
```

Output after parse
```json
{
  "input": "key1=value1,key2=value\\,2,key3='value ,3'",
  "_outField": {
    "key1": "value1",
    "key2": "value,2",
    "key3": "value ,3"
  }
}
```

### Example: Multi-character separator and delimiter

**Parser configuration**

```yaml
parse|input:
- <_outField/kv/::=/ || /"/\\>
```

Input event
```json
{
  "input": "k1::=v1 || k2::=v2"
}
```

Output after parse
```json
{
  "input": "k1::=v1 || k2::=v2",
  "_outField": {
    "k1": "v1",
    "k2": "v2"
  }
}
```

## URI

The uri parser is adept at parsing Uniform Resource Identifiers (URIs) and transforming them into an
[ECS url](https://www.elastic.co/guide/en/ecs/current/ecs-url.html) object encoded as a JSON object.


### Behavior

- Checks the validity of the URI format and components (parsed with libcurl's URL API).
- Decomposes the URI into string members `original`, `scheme`, `domain`, `username`, `password`, `port`, `path`,
  `query` and `fragment`; a part absent from the URI is not set. `original` is the URL as normalised by libcurl (for
  example, an empty path becomes `/`).
- Accepts no parameters.
- Requires an end token to determine the boundary of parsing.

### Signature

```yaml
<field/uri>
```

### Example: Basic URI Parsing

**Parser configuration**

For the following examples, the parser configuration is as follows:
```yaml
parse|input:
- <_outField/uri>
```

**Example 1**

Input event
```json
{
  "input": "http://someurl.com"
}
```

Output after parse
```json
{
  "input": "http://someurl.com",
  "_outField": {
    "original": "http://someurl.com/",
    "scheme": "http",
    "domain": "someurl.com",
    "path": "/"
  }
}
```

**Example 2**

Input event
```json
{
  "input": "https://some.url.com:8080/user.php?name=pepe&param=123#login"
}
```

Output after parse
```json
{
  "input": "https://some.url.com:8080/user.php?name=pepe&param=123#login",
  "_outField": {
    "path": "/user.php",
    "query": "name=pepe&param=123",
    "original": "https://some.url.com:8080/user.php?name=pepe&param=123#login",
    "scheme": "https",
    "fragment": "login",
    "domain": "some.url.com",
    "port": "8080"
  }
}
```

**Example 3**

Input event
```json
{
  "input": "https://john.doe@[2001:db8::7]:123/forum/questions/?tag=networking&order=newest#top"
}
```

Output after parse
```json
{
  "input": "https://john.doe@[2001:db8::7]:123/forum/questions/?tag=networking&order=newest#top",
  "_outField": {
    "domain": "[2001:db8::7]",
    "query": "tag=networking&order=newest",
    "path": "/forum/questions/",
    "original": "https://john.doe@[2001:db8::7]:123/forum/questions/?tag=networking&order=newest#top",
    "scheme": "https",
    "fragment": "top",
    "username": "john.doe",
    "port": "123"
  }
}
```

## FQDN

The `fqdn` (Fully Qualified Domain Name) Parser validates and extracts domain names from text inputs.
It ensures that the domain names adhere to standard domain naming conventions, including character restrictions and
length limitations.

### Behavior

- Validates the format of domain names, ensuring they conform to DNS naming standards.
- Validates that the input string is a valid domain name, adhering to DNS naming rules.
- Consumes the characters "a-z", "A-Z", "0-9", ".", and "-".
- Limits the domain name length to a maximum of 253 characters; the name cannot start with a dot or contain two
  consecutive dots.
- Stores the valid domain name, as a string, in the designated output field if the validation is successful.
- Accepts no parameters.
- It does not require a specific end token


### Signature

```yaml
<field/fqdn>
```

### Example

**Parser configuration**

```yaml
parse|input:
- <_outField/fqdn>
```

Input event
```json
{
  "input": "www.example.com"
}
```

Output after parse
```json
{
  "input": "www.example.com",
  "_outField": "www.example.com"
}
```

## File

The `file` path parser validates and extracts detailed components from file paths provided in text inputs.
This parser is essential for operations where file paths need to be analyzed or decomposed into their constituent
elements such as directory, file name, and extension.

### Behavior

- Takes the text up to the end token as a file path; a path containing `\` is split on `\`, any other on `/`.
- Decomposes the file path into the string members `path` (everything before the last separator), `name` (the part
  after it), `ext` (the text after the last `.` of `name`, lowercased; empty when there is none) and, for a Windows
  path, `drive_letter`.
- Accepts no parameters.
- Requires an end token to determine the boundary of parsing.

### Signature

```yaml
<field/file>
```

### Example

**Parser configuration**

For the following examples, the parser configuration is as follows:
```yaml
parse|input:
- <_outField/file>
```

**Example 1**

Input event
```json
{
  "input": "/path/to/file.txt"
}
```

Output after parse
```json
{
  "input": "/path/to/file.txt",
  "_outField": {
    "path": "/path/to",
    "name": "file.txt",
    "ext": "txt"
  }
}
```

**Example 2**

Input event
```json
{
  "input": "C:\\path\\to\\file.txt"
}
```

Output after parse
```json
{
  "input": "C:\\path\\to\\file.txt",
  "_outField": {
    "path": "C:\\path\\to",
    "name": "file.txt",
    "ext": "txt",
    "drive_letter": "C"
  }
}
```

**Example 3**

Input event
```json
{
  "input": "../home/..user/.rootkit/.file.sh"
}
```

Output after parse
```json
{
  "input": "../home/..user/.rootkit/.file.sh",
  "_outField": {
    "path": "../home/..user/.rootkit",
    "name": ".file.sh",
    "ext": "sh"
  }
}
```

## Ignore

The `ignore` parser is used to skip over specific text sequences within the input data, effectively ignoring them during
the parsing process. This parser is essential for excluding irrelevant or redundant information from the parsing like
spaces, tabs, or other characters that do not contain valuable data.

### Behavior
- Skips over specified text sequences, excluding them from the parsing process.
- Consumes the sequence one or more consecutive times at the current position; it fails if the sequence is not
  there at least once. The match is case-sensitive.
- Takes exactly one non-empty argument, and accepts no destination field: it must be written as `<~/ignore/...>`.
- Does not require an end token.

### Signature

```yaml
<~/ignore/str_to_ignore>
```

- `str_to_ignore`: The specific text sequence to be ignored during parsing.

### Example

**Parser configuration**

For the following examples, the parser configuration is as follows:
```yaml
parse|input:
- Extract only the number:<~/ignore/ ><_number/long>
```

**Example 1**

Input event
```json
{
  "input": "Extract only the number:      1234"
}
```

Output after parse
```json
{
  "input": "Extract only the number:      1234",
  "_number": 1234
}
```

>[!NOTE]
> In this example, the parser ignores all spaces (the ` ` sequence) between the text and the number, extracting only the
> number value with the `long` parser. It is useful when the input data is fixed and the parser needs to skip over
> specific sequences. The `ignore` parser is written with the `~` wildcard, so it stores nothing.


## Between

The `between` parser is designed to extract a substring from an input string, specifically capturing the text that is
located between a designated `start` and `end` delimiters. This parser is highly effective in scenarios where structured
text formats need to be parsed to extract specific data segments enclosed by known markers.

### Behavior
- The input must start with `start`; the parser consumes up to the first occurrence of `end` after it, and stores the
  text in between.
- Takes exactly two arguments, which cannot both be empty.
- End token is not required.

### Signature

```yaml
<field/between/start/end>
```

- `start`: The starting delimiter of the text to be extracted.
- `end`: The ending delimiter of the text to be extracted.

### Examples

**Parser configuration**

For the following examples, the parser configuration is as follows:
```yaml
parse|input:
- "<_outField/between/Extract this text: [/].>"
```

**Example 1**

Input event
```json
{
  "input": "Extract this text: [This is the text to extract]."
}
```

Output after parse
```json
{
  "input": "Extract this text: [This is the text to extract].",
  "_outField": "This is the text to extract"
}
```

## Alphanumeric

The `alphanumeric` parser is designed to validate and extract alphanumeric characters from input strings,
optionally including a specified set of additional characters. This parser is useful for cleaning data fields to ensure
they contain only valid, expected characters.

### Behavior

- Consumes one or more alphanumeric characters, plus any character listed in `additionalChars`, and stops at the
  first other character; it fails if the first character is not allowed.
- Accepts at most one argument.
- Does not require an end token.

### Signature

```yaml
<field/alphanumeric/[additionalChars]>
```

- `additionalChars`: Optional parameter specifying additional characters that are allowed in the input field.

### Examples without additional characters

**Parser configuration**

For the following examples, the parser configuration is as follows:
```yaml
parse|input:
  - <_result/alphanumeric>
```

**Example 1**

Input event
```json
{
  "input": "1234abcd"
}
```

Output after parse
```json
{
  "input": "1234abcd",
  "_result": "1234abcd"
}
```

### Examples with additional characters

**Parser configuration**

```yaml
parse|input:
  - <_result/alphanumeric/_->
```

**Example 1**

Input event
```json
{
  "input": "_123_abc-DEF456"
}
```

Output after parse
```json
{
  "input": "_123_abc-DEF456",
  "_result": "_123_abc-DEF456"
}
```

## Useragent

The `useragent` Parser is tailored for extracting user agent strings from log data and mapping them directly to a
designated field without alteration. It is designed to capture the user agent string in its entirety, preserving all
original information for analytical or tracking purposes.

### Behavior

- The parser takes the text up to the end token, unmodified, and stores it as the `original` member of the output
  field (`<field>.original`). It does not decompose the user agent.
- Accepts no parameters.
- Requires an end token to determine the boundary of parsing.


### Signature

```yaml
<field/useragent>
```

### Examples

**Parser configuration**

For the following examples, the parser configuration is as follows:
```yaml
parse|input:
- <_outField/useragent>
```

**Example 1**

Input event
```json
{
  "input": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3"
}
```

Output after parse
```json
{
  "input": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3",
  "_outField": {
    "original": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3"
  }
}
```
