import threading
import signal
import sys

class InvalidOperationException(Exception):
    pass    

# noinspection PyClassHasNoInit
class GlobalInterruptableThreadHandler:
    threads = []
    initialized = False

    @staticmethod
    def initialize():
        signal.signal(signal.SIGTERM, GlobalInterruptableThreadHandler.sig_handler)
        signal.signal(signal.SIGINT, GlobalInterruptableThreadHandler.sig_handler)
        GlobalInterruptableThreadHandler.initialized = True

    @staticmethod
    def add_thread(thread):
        print threading.current_thread().name
        if threading.current_thread().name != 'MainThread':
            raise InvalidOperationException("Me: InterruptableThread objects may only be started from the Main thread.")

        if not GlobalInterruptableThreadHandler.initialized:
            GlobalInterruptableThreadHandler.initialize()

        GlobalInterruptableThreadHandler.threads.append(thread)

    @staticmethod
    def sig_handler(signum, frame):
        sys.stdout.write("handling signal: %s\n" % signum)
        sys.stdout.flush()

        for thread in GlobalInterruptableThreadHandler.threads:
            thread.stop()

        GlobalInterruptableThreadHandler.threads = []    

class IntThread:
    def __init__(self, target=None, args=None, daemon=False):
        self.stop_requested = threading.Event() 
        if target:
           if args:
              self.t = threading.Thread(target=target, args=args)
           else:
              self.t = threading.Thread(target=target)  
        else:
           self.t = threading.Thread(target=self.run)

        self.isDaemon = False
        if daemon:
          self.t.setDaemon(True)
          self.isDaemon = True

    def run(self):
        pass

    def start(self):
        GlobalInterruptableThreadHandler.add_thread(self)
        self.t.start()

    def stop(self):
        self.stop_requested.set()

    def is_stop_requested(self):
        return self.stop_requested.is_set()

    def join(self):
        try:
            while self.t.is_alive():
                self.t.join(timeout=1)
        except (KeyboardInterrupt, SystemExit):
            self.stop_requested.set()
            self.t.join()

        sys.stdout.write("join completed\n")
        sys.stdout.flush()

