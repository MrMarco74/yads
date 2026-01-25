"""
Deception Scoring System

Calculates confidence scores and risk levels for deception detections.
Combines multiple indicators using weighted scoring with diminishing returns.
"""

from typing import List, Dict, Any, Union
from dataclasses import dataclass

from .honeypots import HoneypotDetection
from .sinkholes import SinkholeDetection
from .tarpits import TarpitDetection


Detection = Union[HoneypotDetection, SinkholeDetection, TarpitDetection]


@dataclass
class DeceptionSummary:
    """Summary of all deception detections for a target."""
    total_detections: int
    highest_confidence: int
    overall_risk: str
    deception_likelihood: str
    honeypot_count: int = 0
    sinkhole_count: int = 0
    tarpit_count: int = 0


class DeceptionScorer:
    """
    Calculates confidence scores and risk levels for deception detections.

    Uses a weighted scoring system with diminishing returns for multiple
    indicators of the same type.
    """

    # Risk level thresholds by detection type
    RISK_THRESHOLDS = {
        "honeypot": {
            "critical": 80,
            "high": 60,
            "medium": 40,
        },
        "sinkhole": {
            "high": 80,
            "medium": 60,
        },
        "tarpit": {
            "high": 70,
            "medium": 50,
        },
    }

    # Deception likelihood thresholds (based on combined confidence)
    LIKELIHOOD_THRESHOLDS = {
        "certain": 90,
        "high": 70,
        "moderate": 50,
        "low": 30,
    }

    def calculate_combined_confidence(self, detections: List[Detection]) -> int:
        """
        Combine multiple detection confidences using weighted scoring.

        Rules:
        1. Start with highest single detection confidence
        2. Add diminishing returns for additional detections
        3. Cap at 99 (never 100% certain)
        4. Different detection types add more than same type

        Args:
            detections: List of detection objects.

        Returns:
            Combined confidence score (0-99).
        """
        if not detections:
            return 0

        # Sort by confidence, highest first
        sorted_detections = sorted(
            detections,
            key=lambda d: d.confidence,
            reverse=True
        )

        # Start with highest confidence
        base = sorted_detections[0].confidence
        bonus = 0

        # Track detection types for cross-type bonus
        seen_types = {self._get_detection_type(sorted_detections[0])}

        for i, detection in enumerate(sorted_detections[1:], 1):
            detection_type = self._get_detection_type(detection)

            # Cross-type detections add more confidence
            if detection_type not in seen_types:
                # 60% of detection's confidence for new type
                bonus += detection.confidence * (0.6 ** i)
                seen_types.add(detection_type)
            else:
                # Same type: diminishing returns
                bonus += detection.confidence * (0.4 ** i)

        return min(99, int(base + bonus))

    def _get_detection_type(self, detection: Detection) -> str:
        """Get the type category of a detection."""
        if isinstance(detection, HoneypotDetection):
            return "honeypot"
        elif isinstance(detection, SinkholeDetection):
            return "sinkhole"
        elif isinstance(detection, TarpitDetection):
            return "tarpit"
        return "unknown"

    def calculate_risk_level(self, detection: Detection) -> str:
        """
        Determine risk level based on detection type and confidence.

        Args:
            detection: A detection object.

        Returns:
            Risk level string: "critical", "high", "medium", or "low".
        """
        detection_type = self._get_detection_type(detection)
        confidence = detection.confidence
        thresholds = self.RISK_THRESHOLDS.get(detection_type, {})

        for level in ["critical", "high", "medium"]:
            if level in thresholds and confidence >= thresholds[level]:
                return level

        return "low"

    def calculate_overall_risk(self, detections: List[Detection]) -> str:
        """
        Calculate overall risk level from all detections.

        Args:
            detections: List of detection objects.

        Returns:
            Overall risk level string.
        """
        if not detections:
            return "none"

        # Get all individual risk levels
        risk_levels = [self.calculate_risk_level(d) for d in detections]

        # Return highest risk
        if "critical" in risk_levels:
            return "critical"
        elif "high" in risk_levels:
            return "high"
        elif "medium" in risk_levels:
            return "medium"
        else:
            return "low"

    def calculate_deception_likelihood(self, detections: List[Detection]) -> str:
        """
        Calculate overall deception likelihood.

        Args:
            detections: List of all detections.

        Returns:
            Likelihood string: "certain", "high", "moderate", "low", or "none".
        """
        if not detections:
            return "none"

        combined_confidence = self.calculate_combined_confidence(detections)

        for likelihood, threshold in self.LIKELIHOOD_THRESHOLDS.items():
            if combined_confidence >= threshold:
                return likelihood

        return "low"

    def create_summary(
        self,
        honeypots: List[HoneypotDetection],
        sinkholes: List[SinkholeDetection],
        tarpits: List[TarpitDetection]
    ) -> DeceptionSummary:
        """
        Create a summary of all deception detections.

        Args:
            honeypots: List of honeypot detections.
            sinkholes: List of sinkhole detections.
            tarpits: List of tarpit detections.

        Returns:
            DeceptionSummary object.
        """
        all_detections: List[Detection] = []
        all_detections.extend(honeypots)
        all_detections.extend(sinkholes)
        all_detections.extend(tarpits)

        if not all_detections:
            return DeceptionSummary(
                total_detections=0,
                highest_confidence=0,
                overall_risk="none",
                deception_likelihood="none",
                honeypot_count=0,
                sinkhole_count=0,
                tarpit_count=0
            )

        highest_confidence = max(d.confidence for d in all_detections)
        combined_confidence = self.calculate_combined_confidence(all_detections)
        overall_risk = self.calculate_overall_risk(all_detections)
        likelihood = self.calculate_deception_likelihood(all_detections)

        return DeceptionSummary(
            total_detections=len(all_detections),
            highest_confidence=highest_confidence,
            overall_risk=overall_risk,
            deception_likelihood=likelihood,
            honeypot_count=len(honeypots),
            sinkhole_count=len(sinkholes),
            tarpit_count=len(tarpits)
        )

    def to_dict(self, summary: DeceptionSummary) -> Dict[str, Any]:
        """Convert summary to dictionary for JSON serialization."""
        return {
            "total_detections": summary.total_detections,
            "highest_confidence": summary.highest_confidence,
            "overall_risk": summary.overall_risk,
            "deception_likelihood": summary.deception_likelihood,
            "honeypot_count": summary.honeypot_count,
            "sinkhole_count": summary.sinkhole_count,
            "tarpit_count": summary.tarpit_count
        }

    def detection_to_dict(self, detection: Detection) -> Dict[str, Any]:
        """Convert a detection object to dictionary."""
        detection_type = self._get_detection_type(detection)

        base = {
            "type": detection_type,
            "confidence": detection.confidence,
            "risk_level": detection.risk_level,
            "indicator": detection.indicator,
        }

        if isinstance(detection, HoneypotDetection):
            base.update({
                "honeypot_type": detection.type,
                "port": detection.port,
                "name": detection.name,
                "details": detection.details
            })
        elif isinstance(detection, SinkholeDetection):
            base.update({
                "domain": detection.domain,
                "sinkhole_ip": detection.sinkhole_ip,
                "sinkhole_operator": detection.sinkhole_operator,
                "detection_type": detection.detection_type,
                "details": detection.details
            })
        elif isinstance(detection, TarpitDetection):
            base.update({
                "tarpit_type": detection.type,
                "port": detection.port,
                "response_delay_ms": detection.response_delay_ms,
                "details": detection.details
            })

        return base
