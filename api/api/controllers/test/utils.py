class CustomMagicMockReturn(dict):
    dikt = {'dikt_key': 'dikt_value'}
    affected_items = [{'id': '001'}]

    def __init__(self):
        super().__init__(self)
        super().__setitem__('data', 'data_value')
        super().__setitem__('message', 'message_value')


class CustomMagicMockReturnEmpty(dict):
    affected_items = []

    def __init__(self):
        super().__init__(self)
