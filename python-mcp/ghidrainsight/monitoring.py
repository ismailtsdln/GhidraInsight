"""Enhanced monitoring and metrics collection for GhidraInsight."""

import time
import psutil
import asyncio
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from collections import defaultdict, deque
import logging
import json

logger = logging.getLogger(__name__)


@dataclass
class MetricPoint:
    """Single metric data point."""
    timestamp: float
    value: float
    labels: Dict[str, str]


@dataclass
class SystemMetrics:
    """System resource metrics."""
    cpu_percent: float
    memory_percent: float
    memory_used_mb: float
    disk_usage_percent: float
    active_connections: int
    timestamp: datetime


@dataclass
class AnalysisMetrics:
    """Analysis operation metrics."""
    total_analyses: int
    successful_analyses: int
    failed_analyses: int
    avg_analysis_time: float
    avg_binary_size: float
    active_analyses: int
    timestamp: datetime


@dataclass
class SecurityMetrics:
    """Security-related metrics."""
    blocked_requests: int
    suspicious_patterns_detected: int
    validation_failures: int
    rate_limited_requests: int
    timestamp: datetime


class MetricsCollector:
    """Collects and manages application metrics."""
    
    def __init__(self, retention_hours: int = 24):
        """
        Initialize metrics collector.
        
        Args:
            retention_hours: How long to retain metric data
        """
        self.retention_hours = retention_hours
        self.retention_seconds = retention_hours * 3600
        
        # Metric storage
        self.system_metrics = deque(maxlen=1000)
        self.analysis_metrics = deque(maxlen=1000)
        self.security_metrics = deque(maxlen=1000)
        self.custom_metrics = defaultdict(lambda: deque(maxlen=1000))
        
        # Counters
        self.counters = defaultdict(int)
        self.gauges = defaultdict(float)
        
        # Start background collection
        self._collection_task = None
        self._running = False
    
    async def start_collection(self, interval_seconds: int = 30):
        """Start background metrics collection."""
        if self._running:
            return
        
        self._running = True
        self._collection_task = asyncio.create_task(self._collect_loop(interval_seconds))
        logger.info("Metrics collection started")
    
    async def stop_collection(self):
        """Stop background metrics collection."""
        self._running = False
        if self._collection_task:
            self._collection_task.cancel()
            try:
                await self._collection_task
            except asyncio.CancelledError:
                pass
        logger.info("Metrics collection stopped")
    
    async def _collect_loop(self, interval_seconds: int):
        """Background collection loop."""
        while self._running:
            try:
                await self._collect_system_metrics()
                await asyncio.sleep(interval_seconds)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Metrics collection error: {e}")
                await asyncio.sleep(interval_seconds)
    
    async def _collect_system_metrics(self):
        """Collect system resource metrics."""
        try:
            # CPU and memory
            cpu_percent = psutil.cpu_percent(interval=1)
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage('/')
            
            # Network connections
            connections = len(psutil.net_connections())
            
            metrics = SystemMetrics(
                cpu_percent=cpu_percent,
                memory_percent=memory.percent,
                memory_used_mb=memory.used / 1024 / 1024,
                disk_usage_percent=disk.percent,
                active_connections=connections,
                timestamp=datetime.utcnow()
            )
            
            self.system_metrics.append(metrics)
            
        except Exception as e:
            logger.error(f"System metrics collection failed: {e}")
    
    def increment_counter(self, name: str, value: int = 1, labels: Dict[str, str] = None):
        """
        Increment a counter metric.
        
        Args:
            name: Counter name
            value: Increment value
            labels: Optional labels
        """
        key = self._make_key(name, labels)
        self.counters[key] += value
    
    def set_gauge(self, name: str, value: float, labels: Dict[str, str] = None):
        """
        Set a gauge metric.
        
        Args:
            name: Gauge name
            value: Gauge value
            labels: Optional labels
        """
        key = self._make_key(name, labels)
        self.gauges[key] = value
    
    def record_timing(self, name: str, duration: float, labels: Dict[str, str] = None):
        """
        Record a timing metric.
        
        Args:
            name: Metric name
            duration: Duration in seconds
            labels: Optional labels
        """
        key = self._make_key(name, labels)
        point = MetricPoint(
            timestamp=time.time(),
            value=duration,
            labels=labels or {}
        )
        self.custom_metrics[key].append(point)
    
    def record_analysis_result(self, success: bool, duration: float, binary_size: int):
        """
        Record analysis operation metrics.
        
        Args:
            success: Whether analysis succeeded
            duration: Analysis duration in seconds
            binary_size: Binary size in bytes
        """
        # Update counters
        self.increment_counter("analyses_total")
        if success:
            self.increment_counter("analyses_successful")
        else:
            self.increment_counter("analyses_failed")
        
        # Record timing
        self.record_timing("analysis_duration", duration)
        
        # Update analysis metrics
        current_time = datetime.utcnow()
        
        # Calculate averages
        total_analyses = self.counters.get("analyses_total", 0)
        successful_analyses = self.counters.get("analyses_successful", 0)
        failed_analyses = self.counters.get("analyses_failed", 0)
        
        avg_duration = self._calculate_average_timing("analysis_duration")
        avg_size = self._calculate_average_binary_size()
        
        metrics = AnalysisMetrics(
            total_analyses=total_analyses,
            successful_analyses=successful_analyses,
            failed_analyses=failed_analyses,
            avg_analysis_time=avg_duration,
            avg_binary_size=avg_size,
            active_analyses=self.gauges.get("active_analyses", 0),
            timestamp=current_time
        )
        
        self.analysis_metrics.append(metrics)
    
    def record_security_event(self, event_type: str, details: Dict[str, str] = None):
        """
        Record security-related metrics.
        
        Args:
            event_type: Type of security event
            details: Event details
        """
        self.increment_counter(f"security_{event_type}")
        
        # Update security metrics
        current_time = datetime.utcnow()
        
        metrics = SecurityMetrics(
            blocked_requests=self.counters.get("security_blocked_requests", 0),
            suspicious_patterns_detected=self.counters.get("security_suspicious_patterns", 0),
            validation_failures=self.counters.get("security_validation_failures", 0),
            rate_limited_requests=self.counters.get("security_rate_limited", 0),
            timestamp=current_time
        )
        
        self.security_metrics.append(metrics)
    
    def get_metrics_summary(self) -> Dict[str, Any]:
        """
        Get comprehensive metrics summary.
        
        Returns:
            Metrics summary dictionary
        """
        current_time = datetime.utcnow()
        
        # System metrics (latest)
        latest_system = self.system_metrics[-1] if self.system_metrics else None
        
        # Analysis metrics (latest)
        latest_analysis = self.analysis_metrics[-1] if self.analysis_metrics else None
        
        # Security metrics (latest)
        latest_security = self.security_metrics[-1] if self.security_metrics else None
        
        # Calculate success rate
        total_analyses = self.counters.get("analyses_total", 0)
        success_rate = 0.0
        if total_analyses > 0:
            successful_analyses = self.counters.get("analyses_successful", 0)
            success_rate = (successful_analyses / total_analyses) * 100
        
        return {
            "timestamp": current_time.isoformat(),
            "system": asdict(latest_system) if latest_system else None,
            "analysis": asdict(latest_analysis) if latest_analysis else None,
            "security": asdict(latest_security) if latest_security else None,
            "counters": dict(self.counters),
            "gauges": dict(self.gauges),
            "success_rate": success_rate,
            "uptime_seconds": self._get_uptime_seconds()
        }
    
    def get_health_status(self) -> Dict[str, Any]:
        """
        Get application health status.
        
        Returns:
            Health status dictionary
        """
        status = "healthy"
        issues = []
        
        # Check system resources
        if self.system_metrics:
            latest = self.system_metrics[-1]
            if latest.cpu_percent > 90:
                status = "degraded"
                issues.append("High CPU usage")
            if latest.memory_percent > 90:
                status = "degraded"
                issues.append("High memory usage")
            if latest.disk_usage_percent > 95:
                status = "critical"
                issues.append("Low disk space")
        
        # Check error rates
        total_analyses = self.counters.get("analyses_total", 0)
        if total_analyses > 10:  # Only check if we have enough samples
            error_rate = (self.counters.get("analyses_failed", 0) / total_analyses) * 100
            if error_rate > 20:  # More than 20% failure rate
                status = "critical"
                issues.append("High analysis failure rate")
            elif error_rate > 10:  # More than 10% failure rate
                status = "degraded"
                issues.append("Elevated analysis failure rate")
        
        # Check security events
        security_events = sum([
            self.counters.get("security_blocked_requests", 0),
            self.counters.get("security_validation_failures", 0),
            self.counters.get("security_suspicious_patterns", 0)
        ])
        if security_events > 100:  # High number of security events
            status = "degraded"
            issues.append("High security event rate")
        
        return {
            "status": status,
            "issues": issues,
            "timestamp": datetime.utcnow().isoformat(),
            "metrics": self.get_metrics_summary()
        }
    
    def _make_key(self, name: str, labels: Dict[str, str] = None) -> str:
        """Create metric key with labels."""
        if not labels:
            return name
        
        label_str = ",".join(f"{k}={v}" for k, v in sorted(labels.items()))
        return f"{name}[{label_str}]"
    
    def _calculate_average_timing(self, metric_name: str) -> float:
        """Calculate average timing for a metric."""
        for key, points in self.custom_metrics.items():
            if key.startswith(metric_name):
                if points:
                    return sum(p.value for p in points) / len(points)
                break
        return 0.0
    
    def _calculate_average_binary_size(self) -> float:
        """Calculate average binary size from analysis metrics."""
        if not self.analysis_metrics:
            return 0.0
        
        # This is a simplified calculation - in practice you'd track actual sizes
        return 1024.0  # Placeholder
    
    def _get_uptime_seconds(self) -> float:
        """Get application uptime in seconds."""
        # This would be set when the application starts
        return 0.0  # Placeholder
    
    def cleanup_old_metrics(self):
        """Remove metrics older than retention period."""
        cutoff_time = time.time() - self.retention_seconds
        
        # Clean custom metrics
        for key, points in self.custom_metrics.items():
            self.custom_metrics[key] = deque(
                (p for p in points if p.timestamp >= cutoff_time),
                maxlen=1000
            )


class AlertManager:
    """Manages alerts based on metrics thresholds."""
    
    def __init__(self, metrics_collector: MetricsCollector):
        """
        Initialize alert manager.
        
        Args:
            metrics_collector: Metrics collector instance
        """
        self.metrics_collector = metrics_collector
        self.alert_thresholds = {
            "cpu_percent": 80.0,
            "memory_percent": 85.0,
            "disk_usage_percent": 90.0,
            "error_rate": 15.0,
            "response_time": 30.0
        }
        self.active_alerts = {}
        self.alert_handlers = []
    
    def add_alert_handler(self, handler):
        """Add alert handler callback."""
        self.alert_handlers.append(handler)
    
    def check_alerts(self):
        """Check metrics against thresholds and trigger alerts."""
        metrics = self.metrics_collector.get_metrics_summary()
        
        alerts = []
        
        # Check system metrics
        if metrics.get("system"):
            system = metrics["system"]
            
            if system["cpu_percent"] > self.alert_thresholds["cpu_percent"]:
                alerts.append({
                    "type": "system",
                    "metric": "cpu_percent",
                    "value": system["cpu_percent"],
                    "threshold": self.alert_thresholds["cpu_percent"],
                    "severity": "warning" if system["cpu_percent"] < 95 else "critical"
                })
            
            if system["memory_percent"] > self.alert_thresholds["memory_percent"]:
                alerts.append({
                    "type": "system",
                    "metric": "memory_percent",
                    "value": system["memory_percent"],
                    "threshold": self.alert_thresholds["memory_percent"],
                    "severity": "warning" if system["memory_percent"] < 95 else "critical"
                })
        
        # Check error rate
        if metrics["success_rate"] < (100 - self.alert_thresholds["error_rate"]):
            alerts.append({
                "type": "application",
                "metric": "error_rate",
                "value": 100 - metrics["success_rate"],
                "threshold": self.alert_thresholds["error_rate"],
                "severity": "warning"
            })
        
        # Process alerts
        for alert in alerts:
            alert_id = f"{alert['type']}_{alert['metric']}"
            
            if alert_id not in self.active_alerts:
                self.active_alerts[alert_id] = alert
                self._trigger_alert(alert)
            else:
                # Update existing alert
                self.active_alerts[alert_id].update(alert)
        
        # Clear resolved alerts
        resolved_alerts = []
        for alert_id, alert in self.active_alerts.items():
            if not self._is_alert_active(alert, metrics):
                resolved_alerts.append(alert_id)
        
        for alert_id in resolved_alerts:
            alert = self.active_alerts.pop(alert_id)
            self._resolve_alert(alert)
    
    def _trigger_alert(self, alert: Dict[str, Any]):
        """Trigger new alert."""
        logger.warning(f"Alert triggered: {alert}")
        
        for handler in self.alert_handlers:
            try:
                handler("triggered", alert)
            except Exception as e:
                logger.error(f"Alert handler failed: {e}")
    
    def _resolve_alert(self, alert: Dict[str, Any]):
        """Resolve alert."""
        logger.info(f"Alert resolved: {alert}")
        
        for handler in self.alert_handlers:
            try:
                handler("resolved", alert)
            except Exception as e:
                logger.error(f"Alert handler failed: {e}")
    
    def _is_alert_active(self, alert: Dict[str, Any], metrics: Dict[str, Any]) -> bool:
        """Check if alert is still active."""
        if alert["type"] == "system" and metrics.get("system"):
            system = metrics["system"]
            current_value = system.get(alert["metric"], 0)
            return current_value > alert["threshold"]
        
        if alert["metric"] == "error_rate":
            current_error_rate = 100 - metrics["success_rate"]
            return current_error_rate > alert["threshold"]
        
        return False


# Global metrics collector
metrics_collector = MetricsCollector()
alert_manager = AlertManager(metrics_collector)


async def start_monitoring():
    """Start global monitoring."""
    await metrics_collector.start_collection()
    logger.info("Global monitoring started")


async def stop_monitoring():
    """Stop global monitoring."""
    await metrics_collector.stop_collection()
    logger.info("Global monitoring stopped")
