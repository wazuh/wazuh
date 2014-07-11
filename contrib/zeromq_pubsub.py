import zmq

context = zmq.Context()
s = context.socket(zmq.SUB)
s.connect("tcp://localhost:11999")
s.setsockopt(zmq.SUBSCRIBE, "")
while 1:
    d = s.recv()
    print d
