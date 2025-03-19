
>[!NOTE]
> - The parsers always take a string as input and return a value of a specific type.
> - The parsers are case-sensitive (Unless otherwise specified).
> - Check the parsing rules here (TODO ADD LINK)

# Schema parser reference

## Boolean parser

The `bool` parser accurately identifies and converts the string representations of `true` and `false` into JSON boolean
types. It is case-insensitive. This parser does not require an end token and is automatically used for fields designated
as boolean types in the schema.

### Behavior

- The Boolean parser strictly matches "true" or "false" without supporting parameters or alternative representations 
    like "yes"/"no" or "on"/"off".
- Is key insensitive.
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
  - <output_field/bool>
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
  "output_field": true
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
  "output_field": false
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
  "output_field": false
}
```

## Long parser

The `long` parser is designed to convert strings into 64-bit signed integers, adhering to the format and range typical
of a long data type in most programming environments. This parser ensures the input string represents a number within
the bounds of -2^63 to 2^63-1. Automatically engaged for schema fields defined as type long.

### Behavior

- Accepts strings that represent integer values, including those prefixed with a '-' sign to denote negative numbers.
- This parser can process numbers with decimal points but discards any fractional part,
  effectively rounding down to the nearest whole number.
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
  - <output_field/long>
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
  "output_field": 123
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
  "output_field": -123
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
  "output_field": 123
}
```

Success  with rounding

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
  "output_field": 1
}
```

## Double parser

The `double` parser processes strings representing double-precision floating-point values,
adhering to the `IEEE 754` standard. It handles a broad range of numeric formats, including
integers, decimals, and numbers in scientific notation. Automatically used for schema fields defined as type `double`.

### Behavior

- Accepts numbers with optional leading '-' signs to indicate negative values.
- Supports numbers with or without a decimal point, and can interpret numbers in scientific notation (e.g., `1.23E+10`).
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
  - <output_field/double>
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
  "output_field": 123.0
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
  "output_field": -123.0
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
  "output_field": 299792458.0
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
  "output_field": 1.23
}
```


## Float parser

The `scaled_float` parser handles strings that represent floating-point values, interpreting them without applying the
scaling factor during the initial parsing phase. This approach allows for high-precision data capture while deferring
scaling to later stages of data processing

### Behavior

- Accepts both integers and decimals, with or without a negative sign.
- Efficiently processes numbers expressed in scientific notation (e.g., 2.5E3).
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
  - <output_field/scaled_float>
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
  "output_field": 123.0
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
  "output_field": -123.0
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
  "output_field": 2500.0
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
  "output_field": 0.01
}
```
## Byte parser

The `byte` parser interprets strings as 8-bit signed integers, handling values from -128 to 127. This parser is crucial
for processing data that fits within a compact numerical range, such as status codes or small counters.
Automatically used for schema fields defined as type `byte`.

### Behavior

- Strictly limits the accepted values to the defined byte range, rejecting inputs outside -128 to 127.
- Does not require a specific end token.
- Accepts numeric strings that may optionally include a '-' sign to indicate negative values.

### Signature

```yaml
<field/byte>
```

### Examples

**Parser configuration**

For the following examples, the parser configuration is as follows:
```yaml
parse|input_field:
  - <status_code/byte>
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
  "status_code": 123
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
  "status_code": -123
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

## Text parser

The Text Parser is designed to extract sequences of characters from an input string up until a specified delimiter or
end token is encountered. It is highly effective for parsing unstructured or semi-structured text, making it particularly
useful for extracting fields from logs or similar textual data sources. Automatically used for schema fields defined as type `keyword` and `text`.

### Behavior

- Captures all characters in the input string until it reaches a designated end token.
- If no specific end token is provided, the parser consumes all characters up to the end of the input string

### Signature

```yaml
<field/text>
```

### Examples: With prefix

**Parser configuration**

For the following examples, the parser configuration is as follows:
```yaml
parse|event.original:
 - "Prefix: <output_field/text>"
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
  "output_field": "This is a test"
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
 - "Prefix: <output_field/text> Suffix"
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
  "output_field": "This is a test"
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
  "output_field": "-"
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

- Extracts and validates IP addresses in both IPv4 and IPv6 formats.
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
  - <output_field/ip>
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
  "output_field": "192.168.1.1"
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
  "output_field": "2001:0db8:85a3:0000:0000:8a2e:0370:7334"
}
```

**Example 3**

Input event
```json
{
  "input_field": "Not an IP address"
}
```

Output after parse
```json
{
  "input_field": "Not an IP address"
}
```
Failed parsing, the input is not a valid IP address.

## Date parser

The `date` parser is essential for transforming date strings into a standardized `ISO 8601` format (`YYYY-MM-DDTHH:MM:SSZ`).  It supports a wide array of date formats, both custom and predefined, ensuring flexibility across different logging systems and internationalization through locale support.  Automatically applied to schema fields defined as type` date`

### Behavior

- Format Matching: Attempts to match the input date string against the specified format.
- Adjustment and Validation: Misformatted or incomplete date entries may result in adjustments based on default values (like assuming the current year when it's missing) or parsing failures, depending on the format's requirements.
- Standardization: Successfully parsed dates are systematically converted to the ISO 8601 format, enhancing data consistency across systems.
- Custom Field Applicability: Can be manually applied to custom fields where specific date parsing is required
- Does not require a specific end token.

### Signature

```yaml
<field/date/Format/[Locale]>
```
- `Format`: Date format string or predefined format name.
- `Locale`: Optional locale string for date parsing. The default locale is "en_US.UTF-8", which handles the most
    commonly encountered date formats.

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
  - <tmp_time/date/RFC3339>
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
  "tmp_time": "2020-01-01T20:04:05.000Z"
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


### Example 2: With locale

**Parser configuration**

For the following examples, the parser configuration is as follows:
```yaml
parse|event_time:
  - <event.start/HTTPDATE/en_GB.UTF-8>
```

> [!NOTE]
> The `date` parser use is implicit, because the parser is automatically applied to schema fields defined as type `date`
> like `event.start`.


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

- Validates base64 encoded strings, ensuring they conform to the base64 encoding standard.
    ensuring the character set includes only A-Z, a-z, 0-9, '+', '/', and '=' for end padding.
- Does not require a specific end token. TODO CHECK

### Signature

```yaml
<field/binary>
```

### Example

**Parser configuration**

For the following examples, the parser configuration is as follows:
```yaml
parse|input_field:
  - <output_field/binary>
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
  "output_field": "Hello, World!"
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

**Input event**

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

- Matches the exact sequence of characters specified in the parser expression.
- Does not require an end token.
- Has 2 modes of syntax: explicit and implicit.

### Signature

**Explicit Usage with Storage**:
Less common, this method involves declaring the literal text along with a destination field for storage, useful in
scenarios where the matched text forms a part of the resultant data

```yaml
<tmp_lit/literal/literal string><src.ip>
```

- `literal string`: The literal text to match

**Implicit Usage**:
More common, this method involves declaring the literal text without a destination field, useful when the matched text
serves as a condition or trigger for subsequent parsing operations

```yaml
deny from <src.ip>
```

>[!NOTE]
> Both forms are used to parse logs like `deny from 66.249.66.167` to extract and store the IP address in src.ip.

### Example

**Parser configuration**

```yaml
parse|event.original:
  - deny from <src.ip>
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
  "src.ip": "1.1.1.1"
}
```

### Example with explicit usage

**Parser configuration**

```yaml
parse|event.original:
  - <tmp_lit/literal/deny from ><src.ip>
```

**Input event**

```json
{
  "event.original": "deny from 1.1.1.1",
}
```

**Output after parse**

```json
{
  "event.original": "deny from 1.1.1.1",
  "src.ip": "1.1.1.1",
  "tmp_lit": "deny from "
}
```

## Quoted

The `quoted` parser is designed to extract sequences of characters that are enclosed by a specified delimiter, often used to handle quoted strings within text. This parser allows the specification of both the delimiter and the escape character, facilitating the accurate parsing of complex string data that may include escaped quotes or nested quotations.

### Behavior

- Supports nested quotations and escaped characters within quoted strings
- By default, the parser uses a double quotation mark (`"`) as the delimiter and a backslash (`\`) as the escape character, but both can be customized to fit different data formats
- No specific end token is required

### Signature

```yaml
<field/quoted/[delim_char]/[esc_char]>
```

- `delim_char`: The character used to denote the beginning and end of the quoted string. The default is the double
    quotation mark (").
- `esc_char`: The character used to escape the delimiter within the string, allowing the delimiter to be used as part of
    the string content. The default is the backslash (`\`).

### Examples

**Parser configuration**

For the following examples, the parser configuration is as follows:
```yaml
parse|event.original:
  - "msg=<temp_quoted/quoted>"
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
  "temp_quoted": "This is a quoted string"
}
```

### Example with custom delimiter and escape character

**Parser configuration**

For the following examples, the parser configuration is as follows:
```yaml
parse|event.original:
  - "msg=<temp_quoted/quoted/'/\\>"
```

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
  "temp_quoted": "This is a quoted string"
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
- Ensures all expected elements are present; fails if the count of extracted values does not match the expected number or if configuration errors occur.
- Requires an end token to determine the boundary of parsing. If positioned at the end of a parser expression, the end of the string acts as the end token.
- Common Errors:
    - Unbalanced Quotes: Fails parsing if quotes enclosing fields are not properly closed, as it cannot accurately determine the boundaries of the quoted text.
    - Insufficient Values: Fails if the number of fields extracted is less than expected; no data is stored.

### Signature

```yaml
<field/quoted/dsv/delim_char/quote_char/esc_char/out[i]>
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
- <outField/dsv/|/'/'/out1/out2/out3/outN>
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
  "outField": {
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
- <outField/dsv/|/'/'/out1/out2/out3>
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
  "outField": {
    "out1": "value-\|-1",
    "out2": "value-'-2",
    "out3": "value-\|'-3"
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
- Properly manages fields enclosed in quotes and respects escape characters, allowing the inclusion of quotes within fields.
- Checks for balanced quotes and the correct number of fields as expected.
- Fails if quotes are unbalanced, fields are missing, or formatting errors occur.
- Requires an end token to determine the boundary of parsing. If positioned at the end of a parser expression, the end of
    the string acts as the end token.


### Signature

```yaml
<field/csv/out[i]>
```

- `out[i]`: The specific field names within the output object where the parsed values will be stored. This argument is
    variadic, allowing multiple fields to be defined for extraction. Each field corresponds to a column in the CSV data.

### Examples

**Parser configuration**

For the following examples, the parser configuration is as follows:
```yaml
parse|input:
- <outField/csv/out1/out2/out3>
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
  "outField": {
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
  "outField": {
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
  "input": "value1,\"value\"\"2\"\",value3"
}
```

Input in string format: `value1,"value""2"",value3`

Output after parse
```json
{
  "input": "value1,\"value\"\"2\"\",value3",
  "outField":{
    "out1": "value1",
    "out2": "value\"2\"",
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

The `parse_json` parser is designed to extract and parse JSON objects embedded within input strings. This parser is
essential for handling structured data formats that include JSON data within text fields, allowing for the extraction of
specific fields from complex JSON structures. This parser is capable of parsing any JSON type, including objects, arrays,
strings, numbers, and booleans.

### Behavior

- Extracts and parses JSON objects embedded within input strings.
- Supports nested JSON structures.
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
- <outField/json>
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
  "outField": {
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
  "outField": {
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
  "outField": 123.45
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
- Text within XML elements is identified with a '#text' key in the JSON output. If no text is present, the key is ignored.
- Ignores the root 'Event' object and maps 'Data' elements using their 'Name' attributes as keys, avoiding array
  tructures for multiple data elements and directly integrating their values into the JSON output.

- End token is required.

### Signature

```yaml
<field/xml/[mode]>
```

- `mode`: Optional parameter specifying the parser mode. If omitted, the default mode is used. For Windows Event Logs,
  use `windows` mode. This mode processes complex XML structures by ignoring repetitive tags like <Event> and uses the
  unique identifiers from <Data> tags directly as keys in the resulting JSON object.

### Examples of Default Mode

**Parser configuration**

For the following examples, the parser configuration is as follows:
```yaml
parse|input:
- <outField/xml>
```

**Example 1**

Input event
```JSON
{
  "input": "<SomeField>Some data</SomeField>"
}
```

Output after parse
```JSON
{
  "input": "<SomeField>Some data</SomeField>",
  "outField": {
    "SomeField": {
      "#text": "Some data"
    }
  }
}
```

**Example 2**

Input event
```JSON
{
  "input": "<SomeField attr1=\"value1\" attr2=\"value2\">Some data</SomeField>"
}
```

Output after parse
```JSON
{
  "input": "<SomeField attr1=\"value1\" attr2=\"value2\">Some data</SomeField>",
  "outField": {
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
```JSON
{
  "input": "<SomeField attr='attr value'><SubField>Some data</SubField></SomeField>"
}
```

Output after parse
```JSON
{
  "input": "<SomeField attr='attr value'><SubField>Some data</SubField></SomeField>",
  "outField": {
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
  "outField": {
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
- <outField/xml/windows>
```

**Example 1**

Input event
```JSON
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
```JSON
{
  "input": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><EventID>5379</EventID></System><EventData><Data Name='SubjectUserName'>vagrant</Data><Data Name='ClientProcessId'>5572</Data></EventData></Event>",
  "outField": {
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
  - Keys are linked to values by the `separator` character.
  - Each key-value pair is split from others, given the `delimiter` character.
  - All the characters contained between the `quote` characters will be considered part of a single value,
    even the `separator` and `delimiting` characters
- Customizable delimiters and separator characters.
- It does not require a end token.

### Signature

```yaml
<field/kv/sep_char/delim_char/quote_char/esc_char>
```

- `sep_char`: Character that separates keys from their corresponding values.
- `delim_char`: Character that delimits one key-value pair from another.
- `quote_char`: Character used for quoting complex values that may contain delimiters or separators as literal content.
- `esc_char`: Character used to escape the quote characters within values, allowing them to be included as part of the data.

### Examples: Simple Key-Value Pair Extraction

**Parser configuration**

```yaml
parse|input:
- <outField/kv/=/,/'/'>
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
  "outField": {
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
- <outField/kv/=/,/'/\\'>
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
  "outField": {
    "key1": "value1",
    "key2": "value,2",
    "key3": "value ,3"
  }
}
```


## URI

The uri parser is adept at parsing Uniform Resource Identifiers (URIs) and transforming them into an
[ECS url](https://www.elastic.co/guide/en/ecs/current/ecs-url.html) object encoded as a JSON object.


### Behavior

- Checks the validity of the URI format and components.
- Decomposes the URI into its constituent parts, including scheme, domain, path, port, query, and fragment.
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
- <outField/uri>
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
  "outField": {
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
  "outField": {
    "path": "/user.php",
    "query": "name=pepe&param=123",
    "Original": "https://some.url.com:8080/user.php?name=pepe&param=123#login",
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
  "outField": {
  	"domain": "[2001:db8::7]",
  	"query": "tag=networking&order=newest",
  	"path": "/forum/questions/",
  	"original": "https://john.doe@[2001:db8::7]:123/forum/questions/?tag=networking&order=newest#top",
  	"scheme": "https",
  	"fragment": "top",
  	"username": "john.doe",
  	"port": "123"
}
```

## FQDN

The `fqdn` (Fully Qualified Domain Name) Parser validates and extracts domain names from text inputs.
It ensures that the domain names adhere to standard domain naming conventions, including character restrictions and
length limitations.

### Behavior

- Validates the format of domain names, ensuring they conform to DNS naming standards.
- Validates that the input string is a valid domain name, adhering to DNS naming rules.
- Allows characters "a-z", "A-Z", "0-9", ".", and "-".
- Limits the domain name length to a maximum of 255 characters.
- Stores the valid domain name in the designated output field if the validation is successful.
- It does not require a specific end token


### Signature

```yaml
<field/fqdn>
```

### Example

**Parser configuration**

```yaml
parse|input:
- <outField/fqdn>
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
  "outField": "www.example.com"
}
```

## File

The `file` path parser validates and extracts detailed components from file paths provided in text inputs.
This parser is essential for operations where file paths need to be analyzed or decomposed into their constituent
elements such as directory, file name, and extension.

### Behavior

- Extracts and validates file paths, ensuring they conform to standard file path naming conventions.
- Decomposes the file path into `path`, `name`, `drive_letter`, and `ext` components.
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
- <outField/file>
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
  "outField": {
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
  "outField": {
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
  "outField": {
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
- Repeatedly ignores the sequence wherever it appears in the input.
- Does not require an end token.

### Signature

```yaml
<field/ignore/str_to_ignore>
```

- `str_to_ignore`: The specific text sequence to be ignored during parsing.

### Example

**Parser configuration**

For the following examples, the parser configuration is as follows:
```yaml
parse|input:
- Extract only the number:<~/ignore/ ><number/long>
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
  "number": 1234
}
```

>[!NOTE]
> In this example, the parser ignores all spaces ('` `' sequence) between the text and the number, extracting only the
> number value with the `long` parser. Is useful when the input data is fixed and the parser needs to skip over specific
> sequences.

>[!NOTE]
> In this example, the parser ignores use as destination the`~` temporary field and not store the value in the output.


## Between

The `between` parser is designed to extract a substring from an input string, specifically capturing the text that is
located between a designated `start` and `end` delimiters. This parser is highly effective in scenarios where structured
text formats need to be parsed to extract specific data segments enclosed by known markers.

### Behavior
- Extracts the text located between the specified `start` and `end` delimiters.
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
- "<outField/between/Extract this text: [/].>"
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
  "outField": "This is the text to extract"
}
```

## Alphanumeric

The `alphanumeric` parser is designed to validate and extract alphanumeric characters from input strings,
optionally including a specified set of additional characters. This parser is useful for cleaning data fields to ensure
they contain only valid, expected characters.

### Behavior

- Checks if the content of the input field consists solely of alphanumeric characters, Optionally includes additional
  characters specified in `additionalChars`.

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
  <result/alphanumeric>
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
  "result": "1234abcd"
}
```

### Examples with additional characters

**Parser configuration**

```yaml
parse|input:
  <result/alphanumeric/_->
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
  "result": "_123_abc-DEF456"
}
```

## Useragent

The `useragent` Parser is tailored for extracting user agent strings from log data and mapping them directly to a
designated field without alteration. It is designed to capture the user agent string in its entirety, preserving all
original information for analytical or tracking purposes.

- The parser takes the content of input field and checks if it is a string.
- If valid, the string is directly mapped to output field under the sub-field original to emphasize that the content is
  unmodified.


### Signature

```yaml
<field/useragent>
```

### Examples

**Parser configuration**

For the following examples, the parser configuration is as follows:
```yaml
parse|input:
- <outField/useragent>
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
  "outField": {
    "original": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3"
  }
}
```
