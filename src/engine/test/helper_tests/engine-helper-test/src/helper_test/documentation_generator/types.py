class Metadata:
    def __init__(self, description: str, keywords: list):
        self.description = description
        self.keywords = keywords


class Argument:
    def __init__(self, arg_type, source, generate, restrictions=None):
        self.arg_type = arg_type
        self.source = source
        self.generate = generate
        self.restrictions = restrictions or {}


class Output:
    def __init__(self, type_: str, subset: str):
        self.type_ = type_
        self.subset = subset


class TargetField:
    def __init__(self, type_: str, subset: str):
        self.type_ = type_
        self.subset = subset


class Restriction:
    def __init__(self, brief, arguments, details):
        self.brief = brief
        self.arguments = arguments
        self.details = details


class Example:
    def __init__(self, arguments, should_pass, description, skipped=False, expected=None):
        self.arguments = arguments
        self.should_pass = should_pass
        self.description = description
        self.skipped = skipped
        self.expected = expected


class Documentation:
    def __init__(
            self, name: str, helper_type: str, is_variadic: bool, metadata: Metadata, arguments: dict, output: Output,
            target_field: TargetField, general_restrictions, examples):
        self.name = name
        self.helper_type = helper_type
        self.is_variadic = is_variadic

        self.description = metadata.description
        self.keywords = metadata.keywords

        self.arguments = arguments
        self.output = output
        self.target_field = target_field
        self.general_restrictions = general_restrictions
        self.examples = examples
