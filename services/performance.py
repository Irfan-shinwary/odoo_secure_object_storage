
import logging
import time
from contextlib import contextmanager


_logger = logging.getLogger(__name__)


class PerformanceTrace:
    """Measure individual stages of secure document operations."""

    def __init__(self, operation, object_name=None, size_bytes=0):
        self.operation = operation
        self.object_name = object_name or "unknown"
        self.size_bytes = size_bytes
        self.started = time.perf_counter()
        self.stages = {}
        self.status = "SUCCESS"

    @contextmanager
    def measure(self, stage):
        started = time.perf_counter()

        try:
            yield
        except Exception:
            self.status = "FAILED"
            raise
        finally:
            elapsed = time.perf_counter() - started
            self.add(stage, elapsed)

    def add(self, stage, elapsed):
        self.stages[stage] = self.stages.get(stage, 0) + elapsed

    def log(self, error=None):
        total = time.perf_counter() - self.started

        details = " ".join(
            f"{name}={elapsed:.4f}s"
            for name, elapsed in self.stages.items()
        )

        message = (
            f"SECURE_STORAGE_PERFORMANCE "
            f"operation={self.operation} "
            f"status={self.status} "
            f"object={self.object_name} "
            f"size_bytes={self.size_bytes} "
            f"{details} "
            f"total={total:.4f}s"
        )

        if error:
            message += f" error_type={type(error).__name__}"

        if self.status == "FAILED":
            _logger.error(message)
        else:
            _logger.info(message)


def timed_iterator(iterable, trace, stage):
    """
    Measure the time spent generating each encrypted/decrypted chunk.

    This measures generator processing time, not the time spent by
    MinIO consuming the chunk.
    """
    iterator = iter(iterable)

    while True:
        started = time.perf_counter()

        try:
            chunk = next(iterator)
        except StopIteration:
            trace.add(stage, time.perf_counter() - started)
            break
        except Exception:
            trace.add(stage, time.perf_counter() - started)
            raise

        trace.add(stage, time.perf_counter() - started)
        yield chunk
