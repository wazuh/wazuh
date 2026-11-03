# Logic Expression Module

## Overview

The **logicexpr** module is a header-only library that compiles boolean logic expressions (e.g., `term1 AND (term2 OR NOT term3)`) into optimized evaluation functions. It implements the classic **Shunting-Yard algorithm** (Dijkstra) to parse infix expressions into postfix notation, builds an expression tree, and then flattens it into a stack-based evaluator for efficient runtime evaluation.

The module is generic — it is parameterized by:
- **Event type**: the data passed to the evaluation function
- **Term type**: the domain-specific operand type
- **Term builder**: a function that converts parsed terms into `bool(Event)` functions
- **Term parser**: a parsec-based parser that extracts terms from the expression string

## Architecture

```
         "term1 AND (term2 OR NOT term3)"
                      │
              ┌───────▼────────┐
              │   Tokenizer    │  parsec-based: terms + operators
              │  (tokenizer.hpp)│  → queue<Token> (infix)
              └───────┬────────┘
                      │
              ┌───────▼────────┐
              │ infixToPostfix │  Shunting-Yard algorithm
              │  (parser.hpp)  │  → stack<Token> (postfix)
              └───────┬────────┘
                      │
              ┌───────▼────────┐
              │  Expression    │  Binary tree from postfix stack
              │  tree build    │  (parser::Expression)
              └───────┬────────┘
                      │
              ┌───────▼────────┐
              │    Visitor     │  Converts parser::Expression →
              │  (logicexpr.hpp)│  evaluator::Expression<Event>
              │                │  using termBuilder for leaves
              └───────┬────────┘
                      │
              ┌───────▼────────┐
              │ getDijstra     │  Flattens tree → vector<Operator>
              │ Evaluator      │  Returns std::function<bool(Event)>
              │ (evaluator.hpp)│  Stack-based evaluation at runtime
              └────────────────┘
```

## Key Concepts

| Concept | Description |
|---|---|
| **Token** | `shared_ptr<BaseToken>` — polymorphic base for terms, operators, and parentheses |
| **TermToken\<T\>** | A leaf token holding a domain-specific build token of type `T` |
| **Operator Tokens** | `OrToken`, `AndToken` (binary), `NotToken` (unary) — templates in `logicexpr::parser::details`, parameterized by a precedence policy |
| **Precedence** | `details::DefaultPrecedencePolicy`: `NOT (3) > AND (2) > OR (1)`. The template `PrecedencePolicy` parameter allows another policy |
| **Tokenizer** | Converts expression string into a `queue<Token>` by alternating between term parsing (parsec) and operator/parenthesis matching |
| **Shunting-Yard** | Transforms infix token queue to postfix token stack, handling operator precedence and parentheses |
| **parser::Expression** | Token-based binary tree built from the postfix stack |
| **evaluator::Expression\<Event\>** | Typed binary tree where leaves hold `function<bool(Event)>` |
| **Dijkstra Evaluator** | Flattened pre-order traversal of the expression tree into a vector, evaluated via a stack-based algorithm at runtime |

## Directory Structure

```
logicexpr/
├── CMakeLists.txt
├── README.md
├── interface/logicexpr/          # Header-only implementation
│   ├── logicexpr.hpp             # buildDijstraEvaluator() — top-level entry point
│   ├── token.hpp                 # Token class hierarchy + precedence policy
│   ├── tokenizer.hpp             # Tokenizer — string → queue<Token>
│   ├── parser.hpp                # Shunting-Yard, Expression tree, parse()
│   └── evaluator.hpp             # evaluator::Expression<Event>, getDijstraEvaluator()
└── test/src/
    ├── token_test.cpp            # Token creation and type checks
    ├── tokenizer_test.cpp        # Tokenizer parsing tests
    ├── parser_test.cpp           # Shunting-Yard and Expression tree tests
    ├── evaluator_test.cpp        # Evaluator function tests
    └── logicexpr_test.cpp        # End-to-end integration tests
```

## Public Interface

### `buildDijstraEvaluator()` ([logicexpr.hpp](interface/logicexpr/logicexpr.hpp))

The main entry point (namespace `logicexpr`) — parses an expression string and returns an evaluation function:

```cpp
template<typename Event, typename TermType, typename TermBuilder, typename TermParser>
std::function<bool(Event)>
buildDijstraEvaluator(const std::string& expression,
                      TermBuilder&& termBuilder,
                      TermParser&& termParser);
```

| Parameter | Description |
|---|---|
| `Event` | The type passed to the evaluator (e.g., `base::Event`) |
| `TermType` | The domain-specific term token type |
| `TermBuilder` | Callable: `TermType → function<bool(Event)>` |
| `TermParser` | A `parsec::Parser` that extracts `TermType` from the expression string |

**Pipeline**: tokenize → Shunting-Yard → build parser::Expression tree → visit tree to create evaluator::Expression\<Event\> using termBuilder → flatten to Dijkstra evaluator function. Any parse error is rethrown as `std::runtime_error` prefixed `Expression parsing failed.`; the `TermBuilder` is called once per term at build time, not per event.

### Token Hierarchy ([token.hpp](interface/logicexpr/token.hpp))

All token types live in namespace `logicexpr::parser`; the operator templates are in its nested `details` namespace.

```
BaseToken (abstract)
├── TermToken<T>              — leaf: holds domain-specific build token
├── details::OpToken<Policy>  — operator base (has precedence)
│   ├── UnaryOpToken<Policy>
│   │   └── NotToken<Policy>  — NOT operator
│   └── BinaryOpToken<Policy>
│       ├── OrToken<Policy>   — OR operator
│       └── AndToken<Policy>  — AND operator
├── ParenthOpenToken          — (
└── ParenthCloseToken         — )
```

`Token` is `std::shared_ptr<BaseToken>`; the aliases `OpToken`, `UnaryOpToken`, `BinaryOpToken`, `OrToken`, `AndToken` and `NotToken` bind the templates to `details::DefaultPrecedencePolicy`.

### Tokenizer ([tokenizer.hpp](interface/logicexpr/tokenizer.hpp))

```cpp
template<typename TermP>
class Tokenizer {
public:
    Tokenizer(TermP termParser);
    std::queue<Token> operator()(std::string_view input) const;
};
```

`TermP` must be a `parsec::Parser` (checked by `static_assert`). At each position it attempts term parsing first (via the provided parser), then falls back to operator/parenthesis matching. Whitespace between tokens is ignored. Empty or whitespace-only input and an unknown token throw `std::runtime_error` carrying the formatted parsec trace.

### Parser ([parser.hpp](interface/logicexpr/parser.hpp))

```cpp
namespace logicexpr::parser {
template<typename TermParser>
std::shared_ptr<Expression> parse(const std::string& rawExpression, TermParser&& termParser);
}
```

- `Expression` — binary tree node with `m_token`, `m_left`, `m_right`
- Utility methods: `visitPreOrder()`, `toDotString()` (Graphviz output)

### Evaluator ([evaluator.hpp](interface/logicexpr/evaluator.hpp))

```cpp
namespace logicexpr::evaluator {
enum class ExpressionType { TERM, OR, AND, NOT };

template<typename Event>
class Expression {
    ExpressionType m_type;
    std::function<bool(Event)> m_function;  // only for TERM nodes
    shared_ptr<Expression> m_left, m_right;
};

template<typename Event>
std::function<bool(Event)> getDijstraEvaluator(
    const shared_ptr<const Expression<Event>>& expression);
}
```

The evaluator flattens the tree into a pre-order vector of operators, then evaluates using a stack machine that processes operators in reverse order — achieving evaluation without recursion at runtime. There is **no short-circuit**: every term function is called on every evaluation.

## Implementation Details

### Shunting-Yard Algorithm

The `infixToPostfix()` function implements Dijkstra's Shunting-Yard:

1. Tokens are consumed from the infix queue.
2. Terms go directly to the output stack.
3. Open parentheses go to the operator stack.
4. Close parentheses pop operators to output until a matching open parenthesis.
5. Operators pop higher-or-equal precedence operators from the operator stack to output, then push themselves.
6. After all tokens, remaining operators are popped to output.

Unbalanced parentheses throw `Parenthesis are not balanced`. A `syntaxChecker` state machine validates that tokens appear in legal order (e.g., no two consecutive terms, no binary operator after open parenthesis).

### Stack-Based Evaluation

`getDijstraEvaluator()` serializes the expression tree via pre-order traversal into a `vector<Operator>`. At runtime, the returned lambda iterates the vector in reverse:
- **TERM**: evaluates `function(event)` and pushes result to `operands` stack
- **NOT**: pops one operand, pushes negation
- **AND**: pops two operands, pushes conjunction
- **OR**: pops two operands, pushes disjunction

This avoids recursion at evaluation time. A single-term expression returns that term's result directly.

### Operator Keywords

| Keyword | Type | Precedence |
|---|---|---|
| `OR` | Binary | 1 (lowest) |
| `AND` | Binary | 2 |
| `NOT` | Unary | 3 (highest) |
| `(` / `)` | Grouping | — |

Keywords are matched case-sensitively (uppercase only), as literal prefixes at the current position, and only after the term parser has failed there.

## CMake Targets

| Target | Type | Description |
|---|---|---|
| `logicexpr` | INTERFACE | Header-only library |
| `logicexpr_test` | Executable | Unit tests (token, tokenizer, parser, evaluator, integration) |

**Key dependencies**: `parsec`, `base`

## Testing

Tests cover each layer independently:

- **`token_test`**: shared-pointer integrity (`getPtr` casting), default and custom precedence policies
- **`tokenizer_test`**: parameterized tokenization of valid and invalid expressions (whitespace, empty input, unknown tokens), and a term parser that swallows operator text
- **`parser_test`**: expression tree construction and utilities, parameterized valid expressions and bad expressions (unbalanced parentheses, syntax errors), non-copyable term types
- **`evaluator_test`**: expression construction and utilities, `getDijstraEvaluator` on AND/OR/NOT trees, a NOT-term tree and a single-term expression
- **`logicexpr_test`**: End-to-end `buildDijstraEvaluator` with mock term builders and parsers

## Consumers

| Consumer | Usage |
|---|---|
| **`builder`** | `checkExpressionBuilder()` in `builder/src/builders/stage/check.cpp` applies the asset's definitions, then calls `buildDijstraEvaluator<base::Event, parsers::HelperToken>` to compile a string `check` expression into a runtime boolean function applied to events |
