"""
Tarpit Detection

Detects network tarpits through timing analysis:
- HTTP tarpits (slow responses, trickling data)
- SMTP tarpits (slow greetings)
- TCP tarpits (connection delays)
"""

import socket
import logging
import time
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from datetime import datetime

import requests

logger = logging.getLogger("yads.deception.tarpits")


# Timing thresholds for tarpit detection
TARPIT_THRESHOLDS = {
    "http": {
        "ttfb_slow_ms": 10000,       # Time to first byte > 10s
        "trickle_rate_bps": 100,     # Less than 100 bytes/sec
        "max_response_time_ms": 60000,  # Response takes > 60s
        "suspiciously_slow_ms": 5000,   # Noticeably slow > 5s
    },
    "smtp": {
        "greeting_delay_ms": 5000,   # SMTP greeting > 5s
        "per_char_delay_ms": 100,    # Character-by-character sending
    },
    "tcp": {
        "connect_delay_ms": 5000,    # SYN-ACK delay > 5s
        "data_delay_ms": 10000,      # Time until data > 10s
        "hold_time_ms": 30000,       # Connection held without data
    },
}


@dataclass
class TarpitDetection:
    """Represents a tarpit detection result."""
    type: str  # "http", "smtp", "tcp"
    port: int
    response_delay_ms: int
    confidence: int
    risk_level: str
    indicator: str
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class TimingMetrics:
    """Container for connection timing measurements."""
    connect_time_ms: float = 0
    time_to_first_byte_ms: float = 0
    total_time_ms: float = 0
    bytes_received: int = 0
    bytes_per_second: float = 0
    is_complete: bool = True
    error: Optional[str] = None


class TarpitDetector:
    """Detects network tarpits through timing analysis."""

    def __init__(self, timeout: int = 30):
        self.timeout = timeout
        self.short_timeout = min(5, timeout)

    def detect_all(self, host: str, ports: List[int] = None) -> List[TarpitDetection]:
        """
        Run all tarpit detection techniques on a host.

        Args:
            host: The target hostname or IP.
            ports: List of ports to check.

        Returns:
            List of TarpitDetection objects.
        """
        if ports is None:
            ports = [80, 443, 25, 22]

        detections = []

        # HTTP tarpit detection
        http_ports = [p for p in ports if p in [80, 443, 8080, 8443]]
        for port in http_ports:
            http_detection = self.detect_http_tarpit(host, port)
            if http_detection:
                detections.append(http_detection)

        # SMTP tarpit detection
        if 25 in ports:
            smtp_detection = self.detect_smtp_tarpit(host, 25)
            if smtp_detection:
                detections.append(smtp_detection)

        # Generic TCP tarpit detection on other ports
        other_ports = [p for p in ports if p not in http_ports and p != 25]
        for port in other_ports:
            tcp_detection = self.detect_tcp_tarpit(host, port)
            if tcp_detection:
                detections.append(tcp_detection)

        return detections

    def detect_http_tarpit(self, host: str, port: int = 80) -> Optional[TarpitDetection]:
        """
        Detect HTTP tarpits through timing analysis.

        Techniques:
        - Measure time to first byte (TTFB)
        - Detect trickling data (slow byte-by-byte transfer)
        - Detect endless responses
        """
        protocol = "https" if port in [443, 8443] else "http"
        url = f"{protocol}://{host}:{port}/" if port not in [80, 443] else f"{protocol}://{host}/"

        metrics = self._measure_http_timing(url)

        if metrics.error:
            logger.debug(f"HTTP timing measurement error for {url}: {metrics.error}")
            return None

        thresholds = TARPIT_THRESHOLDS["http"]

        # Check for very slow TTFB
        if metrics.time_to_first_byte_ms > thresholds["ttfb_slow_ms"]:
            confidence = min(80, 50 + int(metrics.time_to_first_byte_ms / 1000))
            return TarpitDetection(
                type="http",
                port=port,
                response_delay_ms=int(metrics.time_to_first_byte_ms),
                confidence=confidence,
                risk_level=self._calculate_risk(confidence),
                indicator=f"Extremely slow TTFB: {metrics.time_to_first_byte_ms:.0f}ms",
                details={
                    "ttfb_ms": metrics.time_to_first_byte_ms,
                    "total_time_ms": metrics.total_time_ms,
                    "url": url
                }
            )

        # Check for trickling data
        if metrics.bytes_received > 0 and metrics.bytes_per_second < thresholds["trickle_rate_bps"]:
            confidence = min(75, 40 + int(100 / max(1, metrics.bytes_per_second)))
            return TarpitDetection(
                type="http",
                port=port,
                response_delay_ms=int(metrics.total_time_ms),
                confidence=confidence,
                risk_level=self._calculate_risk(confidence),
                indicator=f"Trickling data: {metrics.bytes_per_second:.1f} bytes/sec",
                details={
                    "bytes_per_second": metrics.bytes_per_second,
                    "bytes_received": metrics.bytes_received,
                    "total_time_ms": metrics.total_time_ms,
                    "url": url
                }
            )

        # Check for incomplete/endless response
        if not metrics.is_complete and metrics.total_time_ms > thresholds["max_response_time_ms"]:
            return TarpitDetection(
                type="http",
                port=port,
                response_delay_ms=int(metrics.total_time_ms),
                confidence=70,
                risk_level="high",
                indicator="Response never completed (potential endless tarpit)",
                details={
                    "total_time_ms": metrics.total_time_ms,
                    "bytes_received": metrics.bytes_received,
                    "is_complete": False,
                    "url": url
                }
            )

        # Check for suspiciously slow but not obviously tarpit
        if metrics.time_to_first_byte_ms > thresholds["suspiciously_slow_ms"]:
            return TarpitDetection(
                type="http",
                port=port,
                response_delay_ms=int(metrics.time_to_first_byte_ms),
                confidence=35,
                risk_level="low",
                indicator=f"Slow response: {metrics.time_to_first_byte_ms:.0f}ms TTFB",
                details={
                    "ttfb_ms": metrics.time_to_first_byte_ms,
                    "url": url
                }
            )

        return None

    def _measure_http_timing(self, url: str) -> TimingMetrics:
        """Measure HTTP connection timing."""
        metrics = TimingMetrics()

        try:
            start_time = time.time()

            # Use streaming to detect trickling
            with requests.get(
                url,
                timeout=self.timeout,
                verify=False,  # nosec B501 - intentional: scanner probes potentially invalid/self-signed certs
                stream=True,
                headers={"User-Agent": "YADS-Security-Scanner/1.15.0"}
            ) as response:
                # Time to first byte
                first_chunk = next(response.iter_content(chunk_size=1), None)
                metrics.time_to_first_byte_ms = (time.time() - start_time) * 1000

                if first_chunk:
                    metrics.bytes_received = len(first_chunk)

                    # Read more data with timeout
                    chunk_start = time.time()
                    for chunk in response.iter_content(chunk_size=1024):
                        metrics.bytes_received += len(chunk)

                        # Stop if we've been reading for too long
                        if (time.time() - start_time) > self.timeout:
                            metrics.is_complete = False
                            break

            metrics.total_time_ms = (time.time() - start_time) * 1000

            if metrics.total_time_ms > 0:
                metrics.bytes_per_second = (metrics.bytes_received / metrics.total_time_ms) * 1000

        except requests.exceptions.Timeout:
            metrics.error = "Timeout"
            metrics.is_complete = False
            metrics.total_time_ms = self.timeout * 1000

        except requests.exceptions.ConnectionError as e:
            metrics.error = f"Connection error: {e}"

        except Exception as e:
            metrics.error = str(e)

        return metrics

    def detect_smtp_tarpit(self, host: str, port: int = 25) -> Optional[TarpitDetection]:
        """
        Detect SMTP tarpits through greeting delay analysis.

        SMTP tarpits often:
        - Delay the initial 220 greeting
        - Send characters one at a time
        """
        metrics = self._measure_smtp_timing(host, port)

        if metrics.error:
            logger.debug(f"SMTP timing measurement error for {host}:{port}: {metrics.error}")
            return None

        thresholds = TARPIT_THRESHOLDS["smtp"]

        # Check for slow greeting
        if metrics.time_to_first_byte_ms > thresholds["greeting_delay_ms"]:
            confidence = min(75, 45 + int(metrics.time_to_first_byte_ms / 1000))
            return TarpitDetection(
                type="smtp",
                port=port,
                response_delay_ms=int(metrics.time_to_first_byte_ms),
                confidence=confidence,
                risk_level=self._calculate_risk(confidence),
                indicator=f"Slow SMTP greeting: {metrics.time_to_first_byte_ms:.0f}ms",
                details={
                    "greeting_delay_ms": metrics.time_to_first_byte_ms,
                    "bytes_received": metrics.bytes_received
                }
            )

        # Check for character-by-character sending (trickling)
        if metrics.bytes_received > 0 and metrics.bytes_per_second < 10:
            return TarpitDetection(
                type="smtp",
                port=port,
                response_delay_ms=int(metrics.total_time_ms),
                confidence=65,
                risk_level="high",
                indicator=f"SMTP trickling: {metrics.bytes_per_second:.1f} bytes/sec",
                details={
                    "bytes_per_second": metrics.bytes_per_second,
                    "total_time_ms": metrics.total_time_ms
                }
            )

        return None

    def _measure_smtp_timing(self, host: str, port: int) -> TimingMetrics:
        """Measure SMTP connection timing."""
        metrics = TimingMetrics()

        try:
            start_time = time.time()

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)

            # Connect
            sock.connect((host, port))
            metrics.connect_time_ms = (time.time() - start_time) * 1000

            # Wait for greeting (220)
            greeting_start = time.time()
            data = b""

            while True:
                chunk = sock.recv(1)
                if not chunk:
                    break

                if metrics.bytes_received == 0:
                    metrics.time_to_first_byte_ms = (time.time() - start_time) * 1000

                data += chunk
                metrics.bytes_received += 1

                # Stop when we get a complete line or timeout
                if b"\n" in data or (time.time() - start_time) > self.short_timeout:
                    break

            metrics.total_time_ms = (time.time() - start_time) * 1000
            sock.close()

            if metrics.total_time_ms > 0:
                metrics.bytes_per_second = (metrics.bytes_received / metrics.total_time_ms) * 1000

        except socket.timeout:
            metrics.error = "Timeout"
            metrics.is_complete = False

        except Exception as e:
            metrics.error = str(e)

        return metrics

    def detect_tcp_tarpit(self, host: str, port: int) -> Optional[TarpitDetection]:
        """
        Detect generic TCP tarpits through connection timing.

        Techniques:
        - Measure connection delay
        - Detect connections that are accepted but never send data
        """
        metrics = self._measure_tcp_timing(host, port)

        if metrics.error:
            logger.debug(f"TCP timing measurement error for {host}:{port}: {metrics.error}")
            return None

        thresholds = TARPIT_THRESHOLDS["tcp"]

        # Check for slow connection (SYN-ACK delay)
        if metrics.connect_time_ms > thresholds["connect_delay_ms"]:
            confidence = min(60, 35 + int(metrics.connect_time_ms / 1000))
            return TarpitDetection(
                type="tcp",
                port=port,
                response_delay_ms=int(metrics.connect_time_ms),
                confidence=confidence,
                risk_level=self._calculate_risk(confidence),
                indicator=f"Slow TCP connect: {metrics.connect_time_ms:.0f}ms",
                details={
                    "connect_time_ms": metrics.connect_time_ms
                }
            )

        # Check for connection hold (accepted but no data)
        if (metrics.bytes_received == 0 and
            metrics.total_time_ms > thresholds["data_delay_ms"]):
            return TarpitDetection(
                type="tcp",
                port=port,
                response_delay_ms=int(metrics.total_time_ms),
                confidence=55,
                risk_level="medium",
                indicator="TCP connection held without data",
                details={
                    "hold_time_ms": metrics.total_time_ms,
                    "bytes_received": 0
                }
            )

        return None

    def _measure_tcp_timing(self, host: str, port: int) -> TimingMetrics:
        """Measure TCP connection timing."""
        metrics = TimingMetrics()

        try:
            start_time = time.time()

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)

            # Measure connection time
            sock.connect((host, port))
            metrics.connect_time_ms = (time.time() - start_time) * 1000

            # Try to receive data
            sock.settimeout(self.short_timeout)
            try:
                data = sock.recv(1024)
                metrics.time_to_first_byte_ms = (time.time() - start_time) * 1000
                metrics.bytes_received = len(data)
            except socket.timeout:
                # No data received, but connection was accepted
                pass

            metrics.total_time_ms = (time.time() - start_time) * 1000
            sock.close()

        except socket.timeout:
            metrics.error = "Connection timeout"
            metrics.total_time_ms = self.timeout * 1000

        except ConnectionRefusedError:
            metrics.error = "Connection refused"

        except Exception as e:
            metrics.error = str(e)

        return metrics

    def _calculate_risk(self, confidence: int) -> str:
        """Calculate risk level from confidence score."""
        if confidence >= 70:
            return "high"
        elif confidence >= 50:
            return "medium"
        else:
            return "low"
