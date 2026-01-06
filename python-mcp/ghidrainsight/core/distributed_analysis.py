"""Distributed analysis module using Celery for multi-node processing."""

import logging
from typing import Dict, Any, List, Optional
import asyncio
from concurrent.futures import ThreadPoolExecutor

try:
    from celery import Celery
    from celery.result import AsyncResult
    CELERY_AVAILABLE = True
except ImportError:
    CELERY_AVAILABLE = False
    Celery = None
    AsyncResult = None

from ..config import settings

logger = logging.getLogger(__name__)


class DistributedAnalysisManager:
    """Manager for distributed analysis across multiple nodes."""

    def __init__(self):
        self.celery_app = None
        self.executor = ThreadPoolExecutor(max_workers=4)

        if CELERY_AVAILABLE:
            self._setup_celery()
        else:
            logger.warning("Celery not available - distributed analysis disabled")

    def _setup_celery(self):
        """Setup Celery application for distributed tasks."""
        if not CELERY_AVAILABLE:
            return

        # Configure Celery
        broker_url = getattr(settings, 'celery_broker_url', 'redis://localhost:6379/0')
        result_backend = getattr(settings, 'celery_result_backend', 'redis://localhost:6379/0')

        self.celery_app = Celery(
            'ghidrainsight',
            broker=broker_url,
            backend=result_backend,
            include=['ghidrainsight.core.distributed_tasks']
        )

        # Configure Celery settings
        self.celery_app.conf.update(
            task_serializer='json',
            accept_content=['json'],
            result_serializer='json',
            timezone='UTC',
            enable_utc=True,
            task_routes={
                'ghidrainsight.core.distributed_tasks.analyze_binary_chunk': {'queue': 'analysis'},
                'ghidrainsight.core.distributed_tasks.analyze_binary_parallel': {'queue': 'analysis'},
            },
            task_default_queue='analysis',
            task_default_exchange='analysis',
            task_default_routing_key='analysis',
        )

    async def analyze_distributed_chunks(self, binary_data: bytes, features: List[str]) -> Dict[str, Any]:
        """
        Analyze binary in distributed chunks.
        
        Args:
            binary_data: Binary file content
            features: List of analysis features
            
        Returns:
            Combined analysis results
        """
        if not CELERY_AVAILABLE:
            logger.warning("Distributed analysis not available, falling back to local analysis")
            from .real_analysis import real_analysis_engine
            return real_analysis_engine.analyze_binary(binary_data, features)

        try:
            # Split binary into chunks
            num_chunks = 4
            chunk_size = len(binary_data) // num_chunks
            chunks = []

            for i in range(num_chunks):
                start = i * chunk_size
                end = start + chunk_size if i < num_chunks - 1 else len(binary_data)
                chunk = binary_data[start:end]
                chunks.append((chunk, start, features))

            # Submit distributed tasks
            from .distributed_tasks import analyze_binary_chunk

            task_results = []
            for chunk_data, offset, chunk_features in chunks:
                # Run task asynchronously
                task = analyze_binary_chunk.delay(chunk_data, offset, chunk_features)
                task_results.append(task)

            # Wait for all tasks to complete
            completed_results = []
            for task in task_results:
                try:
                    result = task.get(timeout=300)  # 5 minute timeout
                    completed_results.append(result)
                except Exception as e:
                    logger.error(f"Task failed: {e}")
                    completed_results.append({
                        "error": str(e),
                        "offset": 0,
                        "features": features
                    })

            # Combine results
            return self._combine_distributed_results(completed_results, binary_data)

        except Exception as e:
            logger.error(f"Distributed analysis failed: {e}")
            # Fallback to local analysis
            from .real_analysis import real_analysis_engine
            return real_analysis_engine.analyze_binary(binary_data, features)

    async def analyze_parallel_features(self, binary_data: bytes,
                                      features: List[str]) -> Dict[str, Any]:
        """
        Analyze different features in parallel across distributed nodes.

        Args:
            binary_data: Binary file content
            features: List of analysis features

        Returns:
            Combined analysis results
        """
        if not self.celery_app or not CELERY_AVAILABLE:
            logger.warning("Distributed analysis not available, falling back to local analysis")
            return await analysis_engine.analyze_binary(binary_data, features)

        try:
            from .distributed_tasks import analyze_binary_parallel

            # Submit parallel feature analysis tasks
            task_results = []
            for feature in features:
                task = analyze_binary_parallel.delay(binary_data, [feature])
                task_results.append(task)

            # Wait for completion
            feature_results = {}
            for i, task in enumerate(task_results):
                try:
                    result = task.get(timeout=300)
                    feature_name = features[i]
                    feature_results[feature_name] = result
                except Exception as e:
                    logger.error(f"Feature analysis failed for {features[i]}: {e}")
                    feature_results[features[i]] = {"error": str(e)}

            # Combine results
            return self._combine_parallel_results(feature_results, binary_data)

        except Exception as e:
            logger.error(f"Parallel feature analysis failed: {e}")
            return await analysis_engine.analyze_binary(binary_data, features)

    def _combine_distributed_results(self, chunk_results: List[Dict[str, Any]],
                                   original_binary: bytes) -> Dict[str, Any]:
        """Combine results from distributed chunk analysis."""
        combined = {
            "analysis_type": "distributed_chunked",
            "total_chunks": len(chunk_results),
            "binary_hash": hashlib.sha256(original_binary).hexdigest(),
            "features_analyzed": [],
            "results": {},
            "performance": {
                "distributed_processing": True,
                "chunks_processed": len(chunk_results),
                "total_size": len(original_binary)
            }
        }

        # Combine results from each chunk
        for result in chunk_results:
            if "error" not in result:
                for feature, feature_result in result.get("results", {}).items():
                    if feature not in combined["results"]:
                        combined["results"][feature] = []
                        combined["features_analyzed"].append(feature)

                    # Merge feature results (simplified - extend lists, etc.)
                    if isinstance(feature_result, list):
                        combined["results"][feature].extend(feature_result)
                    elif isinstance(feature_result, dict):
                        if feature not in combined["results"] or not isinstance(combined["results"][feature], dict):
                            combined["results"][feature] = {}
                        combined["results"][feature].update(feature_result)
                    else:
                        combined["results"][feature] = feature_result

        return combined

    def _combine_parallel_results(self, feature_results: Dict[str, Dict[str, Any]],
                                original_binary: bytes) -> Dict[str, Any]:
        """Combine results from parallel feature analysis."""
        combined = {
            "analysis_type": "distributed_parallel",
            "binary_hash": hashlib.sha256(original_binary).hexdigest(),
            "features_analyzed": list(feature_results.keys()),
            "results": {},
            "performance": {
                "parallel_processing": True,
                "features_parallelized": len(feature_results)
            }
        }

        # Combine feature results
        for feature, result in feature_results.items():
            if "error" not in result:
                combined["results"][feature] = result.get("results", {}).get(feature, result)
            else:
                combined["results"][feature] = {"error": result["error"]}

        return combined

    def get_cluster_status(self) -> Dict[str, Any]:
        """Get status of distributed analysis cluster."""
        if not self.celery_app or not CELERY_AVAILABLE:
            return {
                "available": False,
                "reason": "Celery not available",
                "nodes": 0
            }

        try:
            # Get active workers
            inspect = self.celery_app.control.inspect()
            active_workers = inspect.active() or {}
            stats = inspect.stats() or {}

            return {
                "available": True,
                "active_workers": len(active_workers),
                "total_workers": len(stats),
                "active_tasks": sum(len(tasks) for tasks in active_workers.values()),
                "cluster_health": "healthy" if len(stats) > 0 else "no_workers"
            }
        except Exception as e:
            return {
                "available": False,
                "reason": str(e),
                "nodes": 0
            }


# Global distributed analysis manager
distributed_manager = DistributedAnalysisManager()
