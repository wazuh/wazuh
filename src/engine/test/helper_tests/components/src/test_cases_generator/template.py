#!/usr/bin/env python3

from .parser import Parser
import itertools


class Template:
    def __init__(self, parser: Parser):
        self.parser = parser

    def generate_raw_template(self, my_sources=[]) -> list:
        sources = []
        if not my_sources:
            sources = self.parser.get_sources()
        else:
            sources = my_sources
        sources_expanded = []
        for source in sources:
            if source == "both":
                sources_expanded.append(["value", "reference"])
            else:
                sources_expanded.append(source)

        # If an element is a list, we treat it as a single element
        data_processed = [x if isinstance(x, list) else [x] for x in sources_expanded]

        # Generate all possible combinations
        combinations = list(itertools.product(*data_processed))
        return combinations

    def enrichment_template(self):
        # Get the sources from the yaml configuration
        raw_combinations = self.generate_raw_template()

        allowed_args = self.parser.get_allowed_in_dict_format()
        # If no allowed restrictions are found, return the raw combinations
        if not allowed_args:
            return raw_combinations

        # Process combinations
        processed_combinations = []
        for comb in raw_combinations:
            comb_list = [list(comb)]
            for arg_index, allowed_values in allowed_args.items():
                new_comb_list = []
                for partial_comb in comb_list:
                    for allowed in allowed_values:
                        new_partial_comb = list(partial_comb)
                        new_partial_comb[arg_index] = (allowed, new_partial_comb[arg_index])
                        new_comb_list.append(new_partial_comb)
                comb_list = new_comb_list
            processed_combinations.extend([tuple(comb) for comb in comb_list])

        return processed_combinations

    def generate_exception_arguments(self) -> list:
        # Get the raw combinations from the sources
        raw_combinations = self.generate_raw_template()
        exception_conditions = self.parser.get_general_restrictions()

        # If no exception conditions are found, return the raw combinations
        if not exception_conditions:
            return raw_combinations

        # Process combinations based on exception conditions
        processed_combinations = []
        for comb in raw_combinations:
            comb_list = [list(comb)]
            for condition in exception_conditions:
                new_comb_list = []
                for partial_comb in comb_list:
                    new_partial_comb = list(partial_comb)
                    for arg_index, value in condition.items():
                        new_partial_comb[arg_index - 1] = (value, new_partial_comb[arg_index - 1])
                    new_comb_list.append(new_partial_comb)
                comb_list = new_comb_list
            processed_combinations.extend([tuple(comb) for comb in comb_list])

        return processed_combinations

    def generate_template(self):
        if self.parser.get_allowed():
            return self.enrichment_template()
        return self.generate_raw_template()
