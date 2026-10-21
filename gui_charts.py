"""
Native Vector Historical Telemetry Graphs for ServerMon.
Zero external charting dependencies: Pure PySide6 QPainter implementation.
Provides rolling 60-sample buffers, smooth Catmull-Rom/cubic Bezier splines,
gradient fills, and real-time statistical metrics (Min, Max, Avg, P95, Jitter).
"""

import math
from typing import Any, Dict, List, Optional
from PySide6.QtCore import QPointF, QRectF, Qt
from PySide6.QtGui import (
    QBrush,
    QColor,
    QFont,
    QLinearGradient,
    QPainter,
    QPainterPath,
    QPen,
)
from PySide6.QtWidgets import QWidget


# Profile color palette
PROFILE_THEMES = {
    "ping": {
        "stroke": QColor(6, 182, 212),       # Cyan #06b6d4
        "fill_top": QColor(6, 182, 212, 100),
        "unit": "ms",
        "title": "Ping Latency (RTT)",
    },
    "tcp": {
        "stroke": QColor(59, 130, 246),      # Blue #3b82f6
        "fill_top": QColor(59, 130, 246, 100),
        "unit": "ms",
        "title": "TCP Handshake Latency",
    },
    "http": {
        "stroke": QColor(16, 185, 129),      # Emerald #10b981
        "fill_top": QColor(16, 185, 129, 100),
        "unit": "ms",
        "title": "HTTP Response Time",
    },
    "snmp": {
        "stroke": QColor(245, 158, 11),      # Amber #f59e0b
        "fill_top": QColor(245, 158, 11, 100),
        "unit": "%",
        "title": "SNMP Hardware Utilization",
    },
    "traffic": {
        "stroke": QColor(244, 63, 94),       # Rose #f43f5e
        "fill_top": QColor(244, 63, 94, 100),
        "unit": "PPS",
        "title": "Packet Rate (PPS)",
    },
}

DEFAULT_THEME = {
    "stroke": QColor(99, 102, 241),          # Indigo #6366f1
    "fill_top": QColor(99, 102, 241, 100),
    "unit": "",
    "title": "Telemetry History",
}


class HistoricalGraphWidget(QWidget):
    """
    High-performance vector historical graph widget using pure PySide6 QPainter.
    Maintains a rolling 60-sample telemetry buffer and renders anti-aliased
    curves with statistical metrics.
    """

    def __init__(self, profile: str = "ping", parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.profile = profile.strip().lower()
        self.max_samples = 60
        self.samples: List[Dict[str, Any]] = []
        self.setMinimumSize(250, 120)

    def set_data(self, samples: List[Dict[str, Any]]) -> None:
        """Sets the telemetry dataset and requests a widget repaint."""
        if samples is None:
            self.samples = []
        else:
            self.samples = [dict(s) for s in samples][-self.max_samples:]
        self.update()

    def append_sample(self, sample: Dict[str, Any]) -> None:
        """Appends a new sample to the rolling buffer (caps at max_samples)."""
        if sample is not None:
            self.samples.append(dict(sample))
            if len(self.samples) > self.max_samples:
                self.samples = self.samples[-self.max_samples:]
            self.update()

    def _extract_values(self) -> List[float]:
        """Extracts numerical metric values from samples based on current profile."""
        values: List[float] = []
        for s in self.samples:
            if not isinstance(s, dict):
                continue
            val = None
            if self.profile in ("ping", "tcp"):
                val = s.get("latency_ms") if s.get("latency_ms") is not None else s.get("response_time_ms")
            elif self.profile == "http":
                val = s.get("latency_ms") if s.get("latency_ms") is not None else s.get("response_time_ms")
                if val is None:
                    val = s.get("duration_ms")
            elif self.profile == "snmp":
                val = s.get("cpu_load_pct") if s.get("cpu_load_pct") is not None else s.get("value")
                if val is None:
                    val = s.get("latency_ms") if s.get("latency_ms") is not None else s.get("response_time_ms")
            elif self.profile == "traffic":
                val = s.get("pps") if s.get("pps") is not None else s.get("packet_rate_pps")
                if val is None:
                    val = s.get("value")
                if val is None:
                    val = s.get("latency_ms") if s.get("latency_ms") is not None else s.get("response_time_ms")

            if val is None:
                # Generic fallback check
                for candidate in ("latency_ms", "response_time_ms", "duration_ms", "pps", "packet_rate_pps", "cpu_load_pct", "value"):
                    if candidate in s and s[candidate] is not None:
                        val = s[candidate]
                        break

            # Fallback for recorded offline/timeout check samples so they appear on the graph
            if val is None and ("status" in s or "error" in s):
                val = 0.0

            if val is not None:
                try:
                    values.append(float(val))
                except (ValueError, TypeError):
                    pass
        return values

    def get_statistics(self) -> Dict[str, float]:
        """
        Calculates real-time statistical metrics for the active telemetry dataset:
        - min: minimum value observed
        - max: maximum value observed
        - avg: arithmetic mean
        - p95: 95th percentile
        - jitter: mean absolute consecutive sample delta
        """
        values = self._extract_values()
        if not values:
            return {
                "min": 0.0,
                "max": 0.0,
                "avg": 0.0,
                "p95": 0.0,
                "jitter": 0.0,
            }

        min_val = float(min(values))
        max_val = float(max(values))
        avg_val = float(sum(values) / len(values))

        # P95 percentile calculation (nearest rank / standard percentile)
        sorted_vals = sorted(values)
        if len(sorted_vals) == 1:
            p95_val = sorted_vals[0]
        else:
            p95_idx = int(round(0.95 * (len(sorted_vals) - 1)))
            p95_idx = max(0, min(p95_idx, len(sorted_vals) - 1))
            p95_val = float(sorted_vals[p95_idx])

        # Jitter: mean absolute delta between consecutive samples
        if len(values) < 2:
            jitter_val = 0.0
        else:
            deltas = [abs(values[i] - values[i - 1]) for i in range(1, len(values))]
            jitter_val = float(sum(deltas) / len(deltas))

        return {
            "min": min_val,
            "max": max_val,
            "avg": avg_val,
            "p95": p95_val,
            "jitter": jitter_val,
        }

    def paintEvent(self, event) -> None:
        """Pure QPainter anti-aliased vector rendering pipeline."""
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing, True)
        painter.setRenderHint(QPainter.SmoothPixmapTransform, True)

        width = self.width()
        height = self.height()
        theme = PROFILE_THEMES.get(self.profile, DEFAULT_THEME)

        # 1. Dark Slate Canvas Background (#0f172a)
        bg_rect = QRectF(0, 0, width, height)
        painter.fillRect(bg_rect, QColor(15, 23, 42))

        # 2. Draw border
        painter.setPen(QPen(QColor(30, 41, 59), 1))
        painter.drawRect(0, 0, width - 1, height - 1)

        # Layout boundaries
        pad_left = 40
        pad_right = 15
        pad_top = 22
        pad_bottom = 20

        plot_w = max(10, width - pad_left - pad_right)
        plot_h = max(10, height - pad_top - pad_bottom)

        values = self._extract_values()

        # Handle empty telemetry dataset gracefully
        if not values or len(values) == 0:
            painter.setPen(QColor(100, 116, 139))  # Slate 500
            font = QFont("Segoe UI", 9)
            painter.setFont(font)
            painter.drawText(
                bg_rect,
                Qt.AlignCenter,
                f"Waiting for telemetry data... ({theme['title']})",
            )
            return

        # Scale limits
        min_v = min(values)
        max_v = max(values)
        if min_v == max_v:
            min_v = max(0.0, min_v - 5.0)
            max_v = max_v + 5.0
        v_span = max(0.001, max_v - min_v)

        # 3. Horizontal Grid lines and axis labels
        painter.setPen(QPen(QColor(30, 41, 59), 1, Qt.DashLine))
        font_axis = QFont("Segoe UI", 7)
        painter.setFont(font_axis)

        grid_steps = 3
        for step in range(grid_steps + 1):
            ratio = step / grid_steps
            y_pos = pad_top + plot_h - (ratio * plot_h)
            painter.drawLine(int(pad_left), int(y_pos), int(pad_left + plot_w), int(y_pos))

            label_val = min_v + (ratio * v_span)
            painter.setPen(QColor(100, 116, 139))
            painter.drawText(
                QRectF(2, y_pos - 8, pad_left - 6, 16),
                Qt.AlignRight | Qt.AlignVCenter,
                f"{label_val:.1f}",
            )
            painter.setPen(QPen(QColor(30, 41, 59), 1, Qt.DashLine))

        # 4. Map samples to 2D plot coordinates
        points: List[QPointF] = []
        n_pts = len(values)
        for i, val in enumerate(values):
            x = pad_left + (i / max(1, n_pts - 1)) * plot_w if n_pts > 1 else pad_left + (plot_w / 2.0)
            norm_y = (val - min_v) / v_span
            y = pad_top + plot_h - (norm_y * plot_h)
            points.append(QPointF(x, y))

        # 5. Build Smooth Spline Path
        path = QPainterPath()
        path.moveTo(points[0])

        if len(points) == 1:
            path.lineTo(points[0])
        elif len(points) == 2:
            path.lineTo(points[1])
        else:
            # Catmull-Rom to Cubic Bezier spline interpolation
            for i in range(len(points) - 1):
                p0 = points[i - 1] if i > 0 else points[i]
                p1 = points[i]
                p2 = points[i + 1]
                p3 = points[i + 2] if i + 2 < len(points) else points[i + 1]

                c1 = QPointF(
                    p1.x() + (p2.x() - p0.x()) / 6.0,
                    p1.y() + (p2.y() - p0.y()) / 6.0,
                )
                c2 = QPointF(
                    p2.x() - (p3.x() - p1.x()) / 6.0,
                    p2.y() - (p3.y() - p1.y()) / 6.0,
                )
                path.cubicTo(c1, c2, p2)

        # 6. Fill Gradient under Curve
        fill_path = QPainterPath(path)
        fill_path.lineTo(points[-1].x(), pad_top + plot_h)
        fill_path.lineTo(points[0].x(), pad_top + plot_h)
        fill_path.closeSubpath()

        gradient = QLinearGradient(0, pad_top, 0, pad_top + plot_h)
        gradient.setColorAt(0.0, theme["fill_top"])
        gradient.setColorAt(1.0, QColor(15, 23, 42, 0))
        painter.fillPath(fill_path, QBrush(gradient))

        # 7. Stroke Smooth Curve
        painter.setPen(QPen(theme["stroke"], 2, Qt.SolidLine, Qt.RoundCap, Qt.RoundJoin))
        painter.drawPath(path)

        # 8. Data point dots & Status highlights
        for i, pt in enumerate(points):
            sample_ref = self.samples[i] if i < len(self.samples) else {}
            st = str(sample_ref.get("status", "ONLINE")).upper()
            if st == "OFFLINE":
                # Red dot for dropped packet / offline
                painter.setBrush(QColor(239, 68, 68))
                painter.setPen(QPen(QColor(255, 255, 255), 1))
                painter.drawEllipse(pt, 4.0, 4.0)
            elif i == len(points) - 1:
                # Latest point highlight
                painter.setBrush(theme["stroke"])
                painter.setPen(QPen(QColor(255, 255, 255), 1.5))
                painter.drawEllipse(pt, 3.5, 3.5)

        # 9. Top Header Stats Banner
        stats = self.get_statistics()
        painter.setPen(QColor(226, 232, 240))  # Slate 200
        font_header = QFont("Segoe UI", 8, QFont.Bold)
        painter.setFont(font_header)
        title_text = f"{theme['title']} ({theme['unit']})"
        painter.drawText(int(pad_left), 15, title_text)

        font_stats = QFont("Segoe UI", 7)
        painter.setFont(font_stats)
        painter.setPen(QColor(148, 163, 184))  # Slate 400
        stats_text = (
            f"Cur: {values[-1]:.1f}{theme['unit']} | "
            f"Avg: {stats['avg']:.1f} | "
            f"Min: {stats['min']:.1f} | "
            f"Max: {stats['max']:.1f} | "
            f"P95: {stats['p95']:.1f} | "
            f"Jitter: {stats['jitter']:.1f}"
        )
        painter.drawText(
            QRectF(pad_left, 3, plot_w, 15),
            Qt.AlignRight | Qt.AlignVCenter,
            stats_text,
        )
