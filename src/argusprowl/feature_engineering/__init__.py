"""Feature engineering package.

Provides sliding window aggregation, statistical calculations,
and feature vector generation for threat detection.
"""

from argusprowl.feature_engineering.feature_extractor import FeatureExtractor
from argusprowl.feature_engineering.feature_vector import FeatureVector
from argusprowl.feature_engineering.sliding_window import SlidingWindow
from argusprowl.feature_engineering.tls_flow_extractor import TLSFlowFeatureExtractor

__all__ = ["FeatureExtractor", "FeatureVector", "SlidingWindow", "TLSFlowFeatureExtractor"]
