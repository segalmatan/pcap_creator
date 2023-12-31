import random


class Jitter:
    def __init__(self, value, deviation_size):
        self._core_value = value
        self._deviation_size = deviation_size

    @property
    def value(self):
        return int(self._core_value + self._deviation_size * (2 * (random.random() - 0.5)))

    def __int__(self):
        return self.value


class Simulation:
    """
    Simulation of network traffic with timing
    """
    def __init__(self, start_timestamp_ms, ping_ms, ping_deviation_ms):
        self._simulation_time_ms = start_timestamp_ms
        self._ping_jitter_ms = Jitter(ping_ms, ping_deviation_ms)
        self._bps = Jitter(400, 20) # TODO: Configure
        self._records = []

    def simulate_data(self, data=b"", delay_ms=0):
        self._records.append((
            self._simulation_time_ms + delay_ms,
            data
        ))

        self._simulation_time_ms += delay_ms
        self._simulation_time_ms += self._ping_jitter_ms.value
        self._simulation_time_ms += len(data) // self._bps.value

    def records(self):
        for record in self._records:
            yield record
