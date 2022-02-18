import queue
import threading
import selectors

import sys
import hexdump
from commands import SpotifyCommand

class ProxyConnection(object):
    def __init__(self, conns):
        self.conns = set(conns)
        self.incoming_queue = queue.Queue()

        assert len(conns) <= 2
        # self.conn_mapping = dict(zip(conns, reversed(conns)))

        for conn in self.conns:
            conn.remote = self.conns - set(conn)

        self.sel = selectors.DefaultSelector()
        self.network_threads = {}

    # select happens on one thread, which polls sockets for reading/writing
    # main proxy thread waits for incoming messages, processes them depending
    # where they come from, and sends any forward message to the appropriate send queue

    def process_incoming_queue(self):
        while self.process_one():
            pass

    def handle_and_indicate_done(self, conn_src, cmd, payload):
        handler_status = conn_src.handle(cmd, payload)
        self.incoming_queue.task_done()

        return handler_status

    def process_one(self):
        # print 'getting next task...'
        (conn_src, task) = self.incoming_queue.get(block=True)
        cmd, payload = task
        # print 'got task with cmd %r' % cmd

        # process_thread = threading.Thread(target=handle_and_indicate_done, args=[conn_src, cmd, payload])
        # process_thread.start()
        # return process_thread

        task_ok = conn_src.handle(cmd, payload)
        self.incoming_queue.task_done()

        return task_ok


    def run(self):
        for conn in self.conns:
            print(f"Starting select thread for {conn}")

            self.network_threads[conn] = threading.Thread(target=self.select_loop_for_conn, args=[conn])
            self.network_threads[conn].daemon = True
            self.network_threads[conn].start()

        # self.process_thread = threading.Thread(target=self.process_incoming_queue)
        # self.process_thread.daemon = True
        # self.process_thread.start()

        print('joining on network threads')
        for t in self.network_threads.values():
            t.join()
        # self.process_incoming_queue()

    def select_loop_for_conn(self, conn):
        while self.select_on_connection(conn):
            pass

        print('select loop died')

    def select_on_connection(self, conn):
        # print 'selecting, with timeout=5'
        read, write, execptional = select([conn], [conn], [conn], 5)
        for conn in read:
            # print conn, 'is ready to read'
            if conn in execptional:
                print(conn, 'is exceptional, no read today')
                continue

            command, payload = conn.codec.read_packet()
            if command is not None:
                spot_cmd = SpotifyCommand(command)
                # self.incoming_queue.put((conn, (spot_cmd, payload)))
                # process it now, dont' use process queue
                conn.handle(spot_cmd, payload)

        for conn in write:
            # print conn, 'is ready to write'
            while True:
                # if conn.final == False:
                #     # print '\tskipping write since we wait for more data'
                #     break

                try:
                    got_lock = conn.codec.stream_lock.acquire(False)
                    if got_lock:
                        # print '\tacquired stream lock, getting next item in queue'

                        cmd, payload = conn.send_queue.get(block=False)
                        # print '\t%r had non-empty send queue' % conn

                        # if conn.name == 'upstream':
                        #     print 'send', cmd, 'with len', len(payload), 'upstream? "n" for no: '
                        #     do_send = raw_input()
                        #     if do_send != 'n':
                        #         # print 'sending command %r to %r' % (cmd, conn)
                        #         conn.codec.send_encrypted(cmd.value, payload)
                        # else:

                        # print 'sending...'
                        conn.codec.send_encrypted(cmd.value, payload)
                        # print 'done'
                        conn.send_queue.task_done()
                    else:
                        # print '\tcannot acquire stream lock'
                        pass
                except queue.Empty:
                    if got_lock:
                        # print '\treleasing stream lock'
                        conn.codec.stream_lock.release()
                        got_lock = False

                    break
                finally:
                    if got_lock:
                        # print '\treleasing stream lock'
                        conn.codec.stream_lock.release()
                        got_lock = False

        for conn in execptional:
            print('!!! execptional on', conn)
            return False

        # self.process_one()

        return True

class Connection(object):
    # maintains a codec
    # all writes should go to send_queue
    # all recvs go into recv_queue
    # has event to get called on select events (write, read, exp)

    def fileno(self):
        return self.codec.sock.fileno()

    def __init__(self, codec, name):
        self.name = name

        self.codec = codec

        # list of messages to send on this connection
        self.send_queue = queue.Queue()

        # who are we connected to (can be self)
        self.remote = None

        self.handlers = {}

    def __repr__(self):
        return f"{self.name} connection"

    def handle(self, cmd, payload):
        if cmd not in self.handlers:
            print(f"{self!r} received unknown cmd {cmd!r}")
            print('contained the following payload:')
            print(hexdump.hexdump(payload))
            return False

        handler, obj_cls = self.handlers[cmd]
        if obj_cls is not None:
            obj = obj_cls()
            obj.ParseFromString(payload)
            handler(cmd, obj)
        else:
            handler(cmd, payload)

        return True
