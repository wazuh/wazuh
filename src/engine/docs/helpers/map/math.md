# int_calculate

## Signature

```

field: int_calculate(operator, operand_left, operand_right, [...])
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| operator | string | value | mul, div, sub, sum |
| operand_left | number | value or reference | Integers between `-2^63` and `2^63-1` |
| operand_right | number | value or reference | Integers between `-2^63` and `2^63-1` |


## Outputs

| Type | Posible values |
| ---- | -------------- |
| number | Integers between `-2^63` and `2^63-1` |


## Description

The function `int_calculate` performs basic arithmetic operations on integers.
The function receives an operator and two or more operands.
The function applies the operator to the first two operands and then applies the result to the next operand.
The result of the operation is stored in the field `field`.
The function supports the following operators: `sum` (addition), `sub` (subtraction), `mul` (multiplication), and `div` (division).


**Keywords**

- `math` 

## Notes

- Division by zero is not allowed (the function will fail).

- The limit for a 64-bit integer is 2^63-1 and -2^63.

---
