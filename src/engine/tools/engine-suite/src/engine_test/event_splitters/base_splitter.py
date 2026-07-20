
class SplitterEvent():
    '''
    Represents a base class for all event splitters.
    '''

    def __init__(self):
        pass

    def split_events(self, events: list[str]) -> list[str]:
        '''
        Split the events into a list of events.
        '''
        raise NotImplementedError("Method 'split_events' must be implemented in the derived class.")
