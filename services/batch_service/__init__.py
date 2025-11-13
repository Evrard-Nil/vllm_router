from services.batch_service.processor import BatchProcessor
from services.files_service import Storage


def initialize_batch_processor(
    batch_processor_name: str, storage_path: str, storage: Storage
) -> BatchProcessor:
    if batch_processor_name == "local":
        from batch.local_processor import LocalBatchProcessor

        return LocalBatchProcessor(storage_path, storage)
    else:
        raise ValueError(f"Unknown batch processor: {batch_processor_name}")


__all__ = [
    "BatchEndpoint",
    "BatchInfo",
    "BatchRequest",
    "BatchStatus",
    "BatchProcessor",
    "initialize_batch_processor",
]
