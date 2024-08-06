# parse_key_value

## Signature

```

field: parse_key_value(input_field, sep_char, delim_char, quote_char, esc_char, [...])
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| input_field | string | reference | Any string |
| sep_char | string | value | Any string |
| delim_char | string | value | Any string |
| quote_char | string | value | Any string |
| esc_char | string | value | Any string |


## Target Field

| Type | Posible values |
| ---- | -------------- |
| [object, array, string, number, boolean] | - |


## Description

This parser can be used to extract key-value pairs from a keys-values list.
If the parser succeeds, each value will be stored on a field named as its corresponding key.
Keys are linked to values by the “separator” character.
Each key-value pair is split from others, given the “delimiting” character.
Additionally, the user must define a “quoting” and “escaping” character.
All the characters contained between the “quoting” characters will be considered part of  a single value
even the “separator” and “delimiting” characters. If the quoting is not correctly balanced, the parser will fail.
The “escaping” character is used to escape the “quoting” characters that are intended to be used as literal characters.
This helper function is typically used in the map stage.
Checks whether an input fits a keys-values list format and, if it does, such pairs of keys and values are stored as new fields of the event.


**Keywords**

- `parser` 

---
# parse_csv

## Signature

```

field: parse_csv(input_field, out1, out2, out3, [...])
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| input_field | string | reference | Any string |
| out1 | string | value | Any string |
| out2 | string | value | Any string |
| out3 | string | value | Any string |


## Target Field

| Type | Posible values |
| ---- | -------------- |
| object | Any object |


## Description

This parser is just the same as the “dsv” parser, but its delimiter is the “comma”, the quoting and escaping character
are the quotation mark, and they cannot be changed.
It can be used to extract values separated by commas (“comma separated values”).
These values will be stored on user-specified fields (outputs), but only if all the expected outputs are obtained.
Eg, user expects 4 values but only 3 can be obtained, then the parser fails and no value is stored.
All the characters contained between the “quoting” characters will be considered part of a single value
even the “comma” character. If the quoting is not correctly balanced, the parser will fail.
The “escaping” character is used to escape the “quoting” characters that are intended to be used as literal characters.
This helper function is typically used in the map stage.


**Keywords**

- `parser` 

---
# parse_xml

## Signature

```

field: parse_xml(input_field, [...])
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| input_field | string | reference | Any string |


## Target Field

| Type | Posible values |
| ---- | -------------- |
| [object, array, string, number, boolean] | - |


## Description

This parser is designed to interpret and convert strings formatted in XML notation into a JSON object.
It preserves the structure of the original XML in the default mode and provides a specialized
transformation for Windows Event Log XML when the optional "windows" argument is used.


**Keywords**

- `parser` 

---
# parse_uri

## Signature

```

field: parse_uri(input_field, [...])
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| input_field | string | reference | Any string |


## Target Field

| Type | Posible values |
| ---- | -------------- |
| [object, array, string, number, boolean] | - |


## Description

This parser is used to obtain, if possible, information from a valid URI.
The result will be an ECS url object encoded as a JSON string. This parser takes no arguments.
Checks whether an input contains a valid URI format and, if so, it evaluates to true and transforms
it to a ECS url object encoded as a JSON string which is then stored on the field, otherwise it evaluates to false.


**Keywords**

- `parser` 

---
# parse_byte

## Signature

```

field: parse_byte(input_field, [...])
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| input_field | string | reference | Any string |


## Target Field

| Type | Posible values |
| ---- | -------------- |
| [object, array, string, number, boolean] | - |


## Description

Evaluates if the content of the input field is a string representing a numeric value.
If the numeric value is within the range of -128 to 127 (inclusive)
it truncates the number to fit into a byte data type and stores the result in `field`. The operation is case-sensitive.


**Keywords**

- `parser` 

---
# parse_quoted

## Signature

```

field: parse_quoted(input_field, [...])
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| input_field | string | reference | Any string |


## Target Field

| Type | Posible values |
| ---- | -------------- |
| [object, array, string, number, boolean] | - |


## Description

This parser is designed to extract text enclosed in quotation marks from the input string.
It supports custom quotation and escape characters, allowing for flexibility in parsing complex quoted strings.
Evaluates the content of the input field to extract text that is enclosed in the specified `quoted` character
considering any `escape` characters used to include the quotation character within the quoted text.


**Keywords**

- `parser` 

---
# parse_bool

## Signature

```

field: parse_bool(input_field, [...])
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| input_field | string | reference | Any string |


## Target Field

| Type | Posible values |
| ---- | -------------- |
| [object, array, string, number, boolean] | - |


## Description

Checks if an input is the “true” or “false” string and store a boolean value in field according to the string value.
The operation es key insensitive Fail if other value is store in $inField or not exist.


**Keywords**

- `parser` 

---
# parse_useragent

## Signature

```

field: parse_useragent(input_field, [...])
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| input_field | string | reference | Any string |


## Target Field

| Type | Posible values |
| ---- | -------------- |
| [object, array, string, number, boolean] | - |


## Description

This parser is designed to process and map user agent strings.
It does not perform any transformation or parsing in the traditional sense but directly maps
the input user agent string to a specific field in the output.
Takes a reference to a string that represents the user agent of a device or browser.
It directly maps this string to `field` without any modification or parsing.
This function is particularly useful for logging or analyzing user agent strings in their original format.


**Keywords**

- `parser` 

---
# parse_between

## Signature

```

field: parse_between(input_field, start, end, [...])
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| input_field | string | reference | Any string |
| start | string | value | Any string |
| end | string | value | Any string |


## Target Field

| Type | Posible values |
| ---- | -------------- |
| object | Any object |


## Description

Evaluates if the content of the input field is a string that begins with the `start` delimiter and ends
with the `end` delimiter. If so, it extracts the text found between these delimiters
and stores this extracted substring in `field`


**Keywords**

- `parser` 

---
# parse_file

## Signature

```

field: parse_file(input_field, [...])
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| input_field | string | reference | Any string |


## Target Field

| Type | Posible values |
| ---- | -------------- |
| [object, array, string, number, boolean] | - |


## Description

Checks whether an input contains a valid file path and, if so,  it evaluates to true and the extracted data contained
in a JSON object is then stored on the field, otherwise it evaluates to false.


**Keywords**

- `parser` 

---
# parse_dsv

## Signature

```

field: parse_dsv(input_field, delim_char, quote_char, esc_char, out, [...])
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| input_field | string | reference | Any string |
| delim_char | string | value | Any string |
| quote_char | string | value | Any string |
| esc_char | string | value | Any string |
| out | string | value | Any string |


## Target Field

| Type | Posible values |
| ---- | -------------- |
| object | Any object |


## Description

This parser can be used to extract values separated by a specific delimiter (“delimiter separated values”)
which must be a single character. These values will be stored on user-specified fields (outputs)
but only if all the expected outputs are obtained. Eg, user expects 4 values but only 3 can be obtained
then the parser fails and no value is stored.
Additionally to the “delimiting” character, the user must define a “quoting” and “escaping” character.
All the characters contained between the “quoting” characters will be considered part
of  a single value, even the “delimiting” character. If the quoting is not correctly balanced, the parser will fail.
The “escaping” character is used to escape the “quoting” characters that are intended to be used as literal characters.
This helper function is typically used in the map stage.


**Keywords**

- `parser` 

---
# parse_float

## Signature

```

field: parse_float(input_field, [...])
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| input_field | string | reference | Any string |


## Target Field

| Type | Posible values |
| ---- | -------------- |
| object | Any object |


## Description

Evaluates if the content of the input field is a string that can be successfully converted into a floating-point number.
It converts and stores the floating-point number in `field`, as floating-point numbers inherently support decimals.


**Keywords**

- `parser` 

---
# parse_binary

## Signature

```

field: parse_binary(input_field, [...])
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| input_field | string | reference | Any string |


## Target Field

| Type | Posible values |
| ---- | -------------- |
| [object, array, string, number, boolean] | - |


## Description

Evaluates if the content of the input field is a string that accurately represents base64 encoded data.
It checks the string for compliance with the base64 encoding standards, including character set and padding.
If the string is a valid base64 encoded string, it stores the same string in `field` without modification.


**Keywords**

- `parser` 

---
# parse_alphanumeric

## Signature

```

field: parse_alphanumeric(field_to_parse, [...])
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| field_to_parse | string | reference | Any string |


## Target Field

| Type | Posible values |
| ---- | -------------- |
| object | Any object |


## Description

Checks if an input matches an alphanumeric string, and if so, it evaluates to true and the extracted data
contained in a JSON object is stored in the output field; otherwise, it evaluates to false.


**Keywords**

- `parser` 

---
# parse_json

## Signature

```

field: parse_json(input_field, [...])
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| input_field | string | reference | Any string |


## Target Field

| Type | Posible values |
| ---- | -------------- |
| [object, array, string, number, boolean] | - |


## Description

This parser is designed to interpret and convert strings formatted in JSON notation into a JSON.
It is particularly useful for extracting structured data from stringified JSON representations.
Upon invocation, the parser reads the input string and attempts to validate it as a proper JSON format.
If the validation is successful, the input is transformed into a JSON object
which is then assigned to the specified field. If the input is not valid JSON, the parser does not modify the output.


**Keywords**

- `parser` 

---
# parse_ip

## Signature

```

field: parse_ip(input_field, [...])
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| input_field | string | reference | Any string |


## Target Field

| Type | Posible values |
| ---- | -------------- |
| [object, array, string, number, boolean] | - |


## Description

This parser is designed to validate and parse strings representing IP addresses, whether they are in IPv4 or IPv6 format.
Evaluates if the content of the input field is a string that accurately represents an IP address in either IPv4 or IPv6 format.
It checks the string for compliance with IP addressing standards, including the correct notation
and range for IPv4 (four decimal numbers separated by dots, each ranging from 0 to 255)
and the correct format for IPv6 (eight groups of four hexadecimal digits separated by colons).
If the string is a valid IP address, it stores the same string in `field` without modification.


**Keywords**

- `parser` 

---
# parse_fqdn

## Signature

```

field: parse_fqdn(input_field, [...])
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| input_field | string | reference | Any string |


## Target Field

| Type | Posible values |
| ---- | -------------- |
| [object, array, string, number, boolean] | - |


## Description

This parser is used to obtain, if possible, a valid domain name.
Such domain cannot be longer than 255 characters and can only contain “a-z”, “A-Z”, “0-9”, “.” and “-”.
Checks whether an input contains a valid domain name format and, if so, it evaluates to true and is then
stored on the field, otherwise it evaluates to false.


**Keywords**

- `parser` 

---
