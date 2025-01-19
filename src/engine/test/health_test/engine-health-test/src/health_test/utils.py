fields_to_exclude = ['@timestamp']

def filter_nested(data, exclude_keys=fields_to_exclude):
    """
    Filters specific keys in a dictionary, recursively navigating through nested structures.

    :param data: Dictionary to be filtered.
    :param exclude_keys: List of keys (at any level) to exclude, represented in the format "key1.key2".
    :return: New filtered dictionary.
    """
    if exclude_keys is None:
        exclude_keys = []

    def recursive_filter(d, keys_to_exclude):
        """Recursive function to filter specific keys."""
        if not isinstance(d, dict):
            return d  # If it's not a dictionary, return the value as is

        filtered = {}
        for key, value in d.items():
            # Build the full keys for this level
            matched_keys = [k for k in keys_to_exclude if k.startswith(f"{key}.") or k == key]

            if key in keys_to_exclude:
                continue  # Exclude the current key

            # Extract relevant keys for the next level
            subkeys_to_exclude = [k.split('.', 1)[1] for k in matched_keys if '.' in k]
            if isinstance(value, dict):
                # Recursively call to filter in deeper levels
                filtered[key] = recursive_filter(value, subkeys_to_exclude)
            else:
                filtered[key] = value  # Keep non-dictionary values as is
        return filtered

    return recursive_filter(data, exclude_keys)
