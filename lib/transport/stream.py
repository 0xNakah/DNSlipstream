import queue
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor

from lib.transport.encoding import encode
from lib.transport.dns import send_dns_query
from lib.transport.polling import poll_read

class DNSStream:
    def __init__(self, target_domain, encryption_key):
        self.target_domain = target_domain
        self.encryption_key = encryption_key
        self.client_guid = uuid.uuid4().bytes
        self.packet_queue = queue.Queue()
        self._start_polling()

    def _start_polling(self):
        poll_thread = threading.Thread(target=poll_read, args=(self,), daemon=True)
        poll_thread.start()

    def read(self):
        return self.packet_queue.get()

    def write(self, data: bytes):
        init_packet, data_packets = encode(data, True, self.encryption_key, self.target_domain, self.client_guid)
        send_dns_query(init_packet.encode(), self.target_domain)
        with ThreadPoolExecutor(max_workers=8) as executor:
            for packet in data_packets:
                executor.submit(send_dns_query, packet.encode(), self.target_domain)
        return len(data)

def dns_stream(target_domain, encryption_key):
    return DNSStream(target_domain, encryption_key)
