import string
class EPC_state_machine:
    current_state = "null_state"
    next_state = None
    states = [
        ("null_state",("initialised_socket_state")),
        ("initialised_socket_state",("connected_state", "null_state")),
        ("connected_state",("initiated_socket_state",)),
    ]
    def get_current_state(self):
        return self.current_state
    def get_next_state(self):
        return self.next_state
    def step():
        EPC_state_machine.current_state = EPC_state_machine.next_state
    def get_possible_next_states(self):
        """returns tuple of next states"""
        return([i[1] for i in self.states if i[0] == self.current_state][0])
    def set_next_state(self,wanted_next_state: string):
        if wanted_next_state not in self.get_possible_next_states():
            raise Exception("there is no such nextstate")
        self.next_state = wanted_next_state
    def set_current_state(self,state:string):
        self.current_state = state