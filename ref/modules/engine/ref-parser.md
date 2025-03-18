
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

### Example


**Parser configuration**
```yaml
parse|input_field:
  - <output_field/bool>
```

**Input and output after parse****

| input_field string value  | output_field value   | Result         |
|-------------------|---------------------|-|
| "true"            | true                | Success |
| "True"            | true                | Success |
| "TRUE"            | true                | Success |
| "false"           | false               | Success |
| "False"           | false               | Success |
| "FALSE"           | false               | Success |
| "Not a boolean"   |                     | Parser does not match |
| "1"               |                     | Parser does not match |


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

### Example

**Parser configuration**

```yaml
parse|input_field:
  - <output_field/long>
```

**Input and output after parse****

| input_field value  | output_field value   | Result         |
|-------------------|---------------------|-|
| "123"             | 123                 | Success |
| "-123"            | -123                | Success |
| "123.456"         | 123                 | Success  with rounding |
| "Not a number"    |                     | Parser does not match |
| "1.23"            | 1                   | Success with rounding |


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

### Example

**Parser configuration**

```yaml
parse|input_field:
  - <output_field/double>
```

**Input and output after parse****

| input_field value  | output_field value   | Result         |
|-------------------|---------------------|-|
| "123"             | 123.0               | Success |
| "-123"            | -123.0              | Success |
| "2.99792458E8"    | 299792458           | Success |
| "Not a number"    |                     | Parser does not match |
| "abc123"          |                     | Parser does not match |
| "1,234            |                     | Parser does not match, commas are not supported |
| "1.23"            | 1.23                | Success |

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

### Example

**Parser configuration**

```yaml
parse|input_field:
  - <output_field/scaled_float>
```

**Input and output after parse****

| input_field value  | output_field value   | Result         |
|-------------------|---------------------|-|
| "123"             | 123.0               | Success |
| "-123"            | -123.0              | Success |
| "2.5E3"           | 2500.0              | Success |
| "Not a number"    |                     | Parser does not match |
| "1.0E-2"          | 0.01                | Success |

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

### Example

**Parser configuration**

```yaml
parse|input_field:
  - <status_code/byte>
```

**Input and output after parse****

| input_field value  | status_code value   | Result         |
|-------------------|---------------------|-|
| "123"             |                 123 | Success |
| "-123"            |                -123 | Success |
| "-128"            |                -128 | Success |
| "127"             |                 127 | Success |
| "128"             |                     | Parser does not match  (out of range) |
| "Not a number"    |                     | Parser does not match |


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


### Example 1

**Parser configuration**

```yaml
parse|event.original:
 - "Prefix: <output_field/text>"
```

**Input and output after parse****

| event.original value  | output_field value   | Result         |
|----------------------|---------------------|-|
| "Prefix: This is a test" | "This is a test" | Success |
| "Prefix: " |  | Failure, no text to parse |
| "Some text" |  | Failure, no prefix to match |

### Example 2

**Parser configuration**

```yaml
parse|event.original:
 - "Prefix: <output_field/text> Suffix"
```

**Input and output after parse****

| event.original value  | output_field value   | Result         |
|----------------------|---------------------|-|
| "Prefix: This is a test Suffix" | "This is a test" | Success |
| "Prefix: - Suffix" | "-" | Success |
| "Prefix: Suffix" |  | Failure, no text to parse |
| "Some text" |  | Failure, no prefix to match |


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


### Example 1

**Parser configuration**

```yaml
parse|input_field:
  - <output_field/ip>
```

**Input and output after parse****

| input_field value  | output_field value   | Result         |
|-------------------|---------------------|-|
| "192.168.1.1"     | "192.168.1.1"       | Success |
| "2001:0db8:85a3:0000:0000:8a2e:0370:7334" | "2001:0db8:85a3:0000:0000:8a2e:0370:7334" | Success |
| "Not an IP address" |                     | Parser does not match |

### Example 2

**Parser configuration**

```yaml
parse|event.original:
  - Request from <source.ip> completed in <~/long>ms
```

**Input and output after parse****

| event.original value  | source.ip value   | Result         |
|----------------------|---------------------|-|
| "Request from 1.1.1.1 completed in 23ms" | "1.1.1.1" | Success |
| "Request from 2001:0db8:85a3:0000:0000:8a2e:0370:7334 completed in 23ms" | "2001:0db8:85a3:0000:0000:8a2e:0370:7334" | Success |
| "Request from Not an IP address completed in 23ms" |  | Parser does not match |


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

### Example 1

**Parser configuration**

```yaml
parse|event_time:
  - <event.start/RFC3339>
```

**Input and output after parse****
| event_time value              | event.start value          | Result          |
|-------------------------------|----------------------------|-----------------|
| "2020-01-02T03:04:05Z07:00"   | "2020-01-01T20:04:05.000Z" | Success         |
| "Not a date"                  |                            | Parser does not match |
| "2020-01-02T03:04:05"         |                            | Parser does not match, missing timezone |


### Example 2

**Parser configuration**

```yaml
parse|event_time:
  - <event.start/HTTPDATE/en_GB.UTF-8>
```

**Input and output after parse****
| event_time value              | event.start value          | Result          |
|-------------------------------|----------------------------|-----------------|
| "02/Jan/2020:03:04:05 +0000"  | "2020-01-02T03:04:05.000Z" | Success         |
| "Not a date"                  |                            | Parser does not match |
| "02/Jan/2020:03:04:05"        |                            | Parser does not match, missing timezone |

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

```yaml
parse|input_field:
  - <output_field/binary>
```

**Input and output after parse****
| input_field value              | output_field value          | Result          |
|-------------------------------|----------------------------|-----------------|
| "SGVsbG8sIFdvcmxkIQ=="        | "Hello, World!"            | Success         |
| "Not a base64 string"         |                            | Parser does not match |
| "SGVsbG8sIFdvcmxkIQ"          |                            | Parser does not match, missing padding |
| "SGVsbG8sIFdvcmxkIQ@="        |                            | Parser does not match, invalid character |


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

**Input and output after parse****

| event.original value  |  Result         |
|----------------------|---|
| "deny from " | Literal successfully matched, but parser ip <src.ip> does not match |
| "deny from 1.1.1.1" | Literal successfully matched, and parser ip <src.ip> matches |


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

### Example

**Parser configuration**

```yaml
parse|event.original:
  - "msg=<temp_quoted/quoted>"
```

**Input and output after parse****

For this example, we will express the input string in `event.original` as string and not as json string, in this way
we can see the actual string value.

| event.original string value  | temp_quoted string value   | Result         |
|----------------------|---------------------|-|
| `msg="This is a quoted string"` | `This is a quoted string` | Success |
| `msg="This is a \"quoted\" string"` | `This is a "quoted" string` | Success |
| `msg="This is a 'quoted' string"` | `This is a 'quoted' string` | Success |
| `msg="This not a quoted string` |  | Parser does not match, `"` is missing |
| `msg=This is a quoted string` |  | Parser does not match, `"` is missing |

### Example with custom delimiter and escape character

**Parser configuration**

```yaml
parse|event.original:
  - "msg=<temp_quoted/quoted/'/\\>"
```

**Input and output after parse****

| event.original string value  | temp_quoted string value   | Result         |
|----------------------|---------------------|-|
| `msg='This is a quoted string'` | `This is a quoted string` | Success |
| `msg='This is a \'quoted\' string'` | `This is a 'quoted' string` | Success |
| `msg='This is a "quoted" string'` | `This is a "quoted" string` | Success |
| `msg='This not a quoted string` |  | Parser does not match, `'` is missing |
| `msg=This is a quoted string` |  | Parser does not match, `'` is missing |


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


### Example 1: Simple Delimited Data Extraction

**Parser configuration**

```yaml
parse|input:
- <outField/dsv/|/'/'/out1/out2/out3/outN>
```

**Input and output after parse**
| input value  | outField value   | Result         |
|----------------------|---------------------|-|
| "value1\|value2\|value3\|valueN" | <pre><code class="lang-json">{</br>  <span class="hljs-attr">"out1"</span>: <span class="hljs-string">"value1"</span>,</br>  <span class="hljs-attr">"out2"</span>: <span class="hljs-string">"value2"</span>,</br>  <span class="hljs-attr">"out3"</span>: <span class="hljs-string">"value3"</span>,</br>  <span class="hljs-attr">"outN"</span>: <span class="hljs-string">"valueN"</span></br>}</br></code></pre> | Success |
| "value1\|value2\|value3" |  | Parser does not match, missing field outN |
| "value1\|value2" |  | Parser does not match, missing fields outN and out3 |


### Example 2: Complex Quoted and Escaped Values

**Parser configuration**

```yaml
parse|input:
- <outField/dsv/|/'/'/out1/out2/out3>
```

**Input and output after parse**
| input value  | outField value   | Result         |
|----------------------|---------------------|-|
|  `'value-\|-1'\|'value-''-2'\|'value-\|''-3'` | <pre><code class="lang-json">{</br>  <span class="hljs-attr">"out1"</span>: <span class="hljs-string">"value-\|-1"</span>,</br>  <span class="hljs-attr">"out2"</span>: <span class="hljs-string">"value-'-2"</span>,</br>  <span class="hljs-attr">"out3"</span>: <span class="hljs-string">"value-\|'-3"</span></br>}</br></code></pre>| Success |

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

### Example

**Parser configuration**

```yaml
parse|input:
- <outField/csv/out1/out2/out3>
```

**Input and output after parse**

| input value  | outField value   | Result         |
|----------------------|---------------------|-|
| "value1,value2,value3" | <pre><code class="lang-json">{</br>  <span class="hljs-attr">"out1"</span>: <span class="hljs-string">"value1"</span>,</br>  <span class="hljs-attr">"out2"</span>: <span class="hljs-string">"value2"</span>,</br>  <span class="hljs-attr">"out3"</span>: <span class="hljs-string">"value3"</span></br>}</br></code></pre> | Success |
| "value1,value2" |  | Parser does not match, missing field out3 |
| "value1" |  | Parser does not match, missing fields out2 and out3 |
| `value1,"value,2",value3` | <pre><code class="lang-json">{</br>  <span class="hljs-attr">"out1"</span>: <span class="hljs-string">"value1"</span>,</br>  <span class="hljs-attr">"out2"</span>: <span class="hljs-string">"value,2"</span>,</br>  <span class="hljs-attr">"out3"</span>: <span class="hljs-string">"value3"</span></br>}</br></code></pre> | Success |
| `value1,"value""2"",value3` | <pre><code class="lang-json">{</br>  <span class="hljs-attr">"out1"</span>: <span class="hljs-string">"value1"</span>,</br>  <span class="hljs-attr">"out2"</span>: <span class="hljs-string">"value\\\"2\\\""</span>,</br>  <span class="hljs-attr">"out3"</span>: <span class="hljs-string">"value3"</span></br>}</br></code></pre> | Success |
