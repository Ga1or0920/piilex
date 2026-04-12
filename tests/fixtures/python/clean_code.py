from typing import List


def calculate_average(numbers: List[float]) -> float:
    if not numbers:
        return 0.0
    return sum(numbers) / len(numbers)


class Config:
    def __init__(self, port: int = 8080, debug: bool = False):
        self.port = port
        self.debug = debug

    def is_production(self) -> bool:
        return not self.debug


def format_timestamp(ts: int) -> str:
    from datetime import datetime
    return datetime.fromtimestamp(ts).isoformat()
