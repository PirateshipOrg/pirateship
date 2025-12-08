# Copyright(C) Facebook, Inc. and its affiliates.
from copy import deepcopy
from datetime import datetime
from glob import glob
from multiprocessing import Pool
from os.path import join
from re import findall, search
from statistics import mean, median
import pandas as pd
import numpy as np
from pathlib import Path
import json



class ParseError(Exception):
    pass

# class LogParser:
#     def __init__(self, clients, primaries, workers, faults=0):
#         inputs = [clients, primaries, workers]
#         assert all(isinstance(x, list) for x in inputs)
#         assert all(isinstance(x, str) for y in inputs for x in y)
#         assert all(x for x in inputs)

#         self.faults = faults
#         if isinstance(faults, int):
#             self.committee_size = len(primaries) + int(faults)
#             self.workers = len(workers) // len(primaries)
#         else:
#             self.committee_size = '?'
#             self.workers = '?'

#         # Parse the clients logs.
#         try:
#             with Pool() as p:
#                 results = p.map(self._parse_clients, clients)
#         except (ValueError, IndexError, AttributeError) as e:
#             raise ParseError(f'Failed to parse clients\' logs: {e}')
#         self.size, self.rate, self.start, misses, self.sent_samples \
#             = zip(*results)
#         self.misses = sum(misses)

#         # Parse the primaries logs.
#         try:
#             with Pool() as p:
#                 results = p.map(self._parse_primaries, primaries)
#         except (ValueError, IndexError, AttributeError) as e:
#             raise ParseError(f'Failed to parse nodes\' logs: {e}')
#         proposals, commits, self.configs, primary_ips, client_latencies = zip(*results)
#         self.proposals = self._merge_results([x.items() for x in proposals])
#         self.commits = self._merge_results([x.items() for x in commits])
#         self.all_commits = self._pile_results([x.items() for x in commits])

#         self.client_latencies = self._avg_results(client_latencies)

#         # Parse the workers logs.
#         try:
#             with Pool() as p:
#                 results = p.map(self._parse_workers, workers)
#         except (ValueError, IndexError, AttributeError) as e:
#             raise ParseError(f'Failed to parse workers\' logs: {e}')
#         sizes, self.received_samples, workers_ips = zip(*results)
#         self.sizes = {
#             k: v for x in sizes for k, v in x.items() if k in self.commits
#         }

#         # Determine whether the primary and the workers are collocated.
#         self.collocate = set(primary_ips) == set(workers_ips)

#         # Check whether clients missed their target rate.
#         if self.misses != 0:
#             print(
#                 f'Clients missed their target rate {self.misses:,} time(s)'
#             )

#     def _merge_results(self, input):
#         # Keep the earliest timestamp.
#         merged = {}
#         for x in input:
#             for k, v in x:
#                 if not k in merged or merged[k] > v:
#                     merged[k] = v
#         return merged
    
#     def _avg_results(self, input):
#         # Keep the earliest timestamp.
#         merged = {}
#         for x in input:
#             for k, v in x.items():
#                 if not k in merged:
#                     merged[k] = [v]
#                 else:
#                     merged[k].append(v)

#         merged = {k: mean(v) for k, v in merged.items()}
#         return merged
    
#     def _pile_results(self, input):
#         merged = {}
#         for x in input:
#             for k, v in x:
#                 if not k in merged:
#                     merged[k] = [v]
#                 else:
#                     merged[k].append(v)

#         return merged

#     def _parse_clients(self, log):
#         # if search(r'Error', log) is not None:
#         #     raise ParseError('Client(s) panicked')

#         size = int(search(r'Transactions size: (\d+)', log).group(1))
#         rate = int(search(r'Transactions rate: (\d+)', log).group(1))

#         tmp = search(r'\[(.*Z) .* Start ', log).group(1)
#         start = self._to_posix(tmp)

#         misses = len(findall(r'rate too high', log))

#         tmp = findall(r'\[(.*Z) .* sample transaction (\d+)', log)
#         samples = {int(s): self._to_posix(t) for t, s in tmp}

#         # tmp = findall(r'Client latency: (\d+) ms', log)
#         # client_latencies = [int(x) for x in tmp]
#         # if len(client_latencies) == 0:
#         #     client_latencies = [0]

#         return size, rate, start, misses, samples

#     def _parse_primaries(self, log):
#         # if search(r'(?:panicked|Error)', log) is not None:
#         #     raise ParseError('Primary(s) panicked')

#         tmp = findall(r'\[(.*Z) .* Created B\d+\([^ ]+\) -> ([^ ]+=)', log)
#         tmp = [(d, self._to_posix(t)) for t, d in tmp]
#         proposals = self._merge_results([tmp])

#         tmp = findall(r'\[(.*Z) .* Committed B\d+\([^ ]+\) -> ([^ ]+=)', log)
#         tmp = [(d, self._to_posix(t)) for t, d in tmp]
#         commits = self._merge_results([tmp])

#         latencies = {}
#         for d in commits.keys():
#             if d in proposals:
#                 latencies[d] = commits[d] - proposals[d]

        


#         configs = {
#             #'timeout_delay': int(
#             #    search(r'Timeout delay .* (\d+)', log).group(1)
#             #),
#             'header_size': int(
#                 search(r'Header size .* (\d+)', log).group(1)
#             ),
#             'max_header_delay': int(
#                 search(r'Max header delay .* (\d+)', log).group(1)
#             ),
#             'gc_depth': int(
#                 search(r'Garbage collection depth .* (\d+)', log).group(1)
#             ),
#             'sync_retry_delay': int(
#                 search(r'Sync retry delay .* (\d+)', log).group(1)
#             ),
#             'sync_retry_nodes': int(
#                 search(r'Sync retry nodes .* (\d+)', log).group(1)
#             ),
#             'batch_size': int(
#                 search(r'Batch size .* (\d+)', log).group(1)
#             ),
#             'max_batch_delay': int(
#                 search(r'Max batch delay .* (\d+)', log).group(1)
#             ),
#         }

#         ip = search(r'booted on (\d+.\d+.\d+.\d+)', log).group(1)

#         return proposals, commits, configs, ip, latencies

#     def _parse_workers(self, log):
#         # if search(r'(?:panic|Error)', log) is not None:
#         #     raise ParseError('Worker(s) panicked')

#         tmp = findall(r'Batch ([^ ]+) contains (\d+) B', log)
#         sizes = {d: int(s) for d, s in tmp}

#         tmp = findall(r'Batch ([^ ]+) contains sample tx (\d+)', log)
#         samples = {int(s): d for d, s in tmp}

#         ip = search(r'booted on (\d+.\d+.\d+.\d+)', log).group(1)

#         return sizes, samples, ip

#     def _to_posix(self, string):
#         x = datetime.fromisoformat(string.replace('Z', '+00:00'))
#         return datetime.timestamp(x)

#     def _consensus_throughput(self):
#         if not self.commits:
#             return 0, 0, 0
#         start, end = min(self.proposals.values()), max(self.commits.values())
#         duration = end - start
#         bytes = sum(self.sizes.values())
#         bps = bytes / duration
#         tps = bps / self.size[0]
#         return tps, bps, duration

#     def _consensus_latency(self):
#         # return 0
#         # latency = [c - self.proposals[d] for d, c in self.commits.items()]

#         # # latency = [x for x in latency if x > 0]
#         # # print(mean(list(self.client_latencies.values())))
#         latency = list(self.client_latencies.values())
#         return mean(latency) if latency else 0

#     def _end_to_end_throughput(self):
#         if not self.commits:
#             return 0, 0, 0
#         start, end = min(self.start), max(self.commits.values())
#         duration = end - start
#         bytes = sum(self.sizes.values())
#         bps = bytes / duration
#         tps = bps / self.size[0]
#         return tps, bps, duration

#     def _end_to_end_latency(self):
#         # return 0
#         latency = []
#         list_latencies = []
#         first_start = 0
#         set_first = True
#         for received in self.received_samples:
#             for tx_id, batch_id in received.items():
#                 if batch_id in self.commits:
#                     # assert tx_id in sent  # We receive txs that we sent.
#                     for _sent in self.sent_samples:
#                         if tx_id in _sent:
#                             start = _sent[tx_id]
#                             possible_ends = self.all_commits[batch_id]
#                             impossible_ends = [x for x in possible_ends if x < start]
#                             if len(impossible_ends) > 0:
#                                 print("batch:", batch_id, "tx:", tx_id, "impossible_ends:", impossible_ends)
#                             possible_ends = [x for x in possible_ends if x > start]

#                             if len(possible_ends) == 0:
#                                 continue
#                             end = min(possible_ends)
#                             if set_first:
#                                 first_start = start
#                                 first_end = end
#                                 set_first = False
#                             latency += [end-start]
#                             list_latencies += [(start-first_start, end-first_start, end-start)]

#         list_latencies.sort(key=lambda tup: tup[0])
#         with open('latencies.txt', 'w') as f:
#             for line in list_latencies:
#                 f.write(str(line[0]) + ',' + str(line[1]) + ',' + str((line[2])) + '\n')
#         # latency = [x for x in latency if x > 0]
#         return mean(latency) if latency else 0

#     def result(self):
#         #timeout_delay = self.configs[0]['timeout_delay']
#         header_size = self.configs[0]['header_size']
#         max_header_delay = self.configs[0]['max_header_delay']
#         gc_depth = self.configs[0]['gc_depth']
#         sync_retry_delay = self.configs[0]['sync_retry_delay']
#         sync_retry_nodes = self.configs[0]['sync_retry_nodes']
#         batch_size = self.configs[0]['batch_size']
#         max_batch_delay = self.configs[0]['max_batch_delay']

#         consensus_latency = self._consensus_latency() * 1_000
#         consensus_tps, consensus_bps, _ = self._consensus_throughput()
#         end_to_end_tps, end_to_end_bps, duration = self._end_to_end_throughput()
#         end_to_end_latency = self._end_to_end_latency() * 1_000

#         # client_latencies = []
#         # for c in self.client_latencies:
#         #     client_latencies.extend(c)
#         # client_latency = mean(client_latencies)

#         # if client_latency > 400:
#         #     raise ParseError('Client latency is too high')

#         return (
#             '\n'
#             '-----------------------------------------\n'
#             ' SUMMARY:\n'
#             '-----------------------------------------\n'
#             ' + CONFIG:\n'
#             f' Faults: {self.faults} node(s)\n'
#             f' Committee size: {self.committee_size} node(s)\n'
#             f' Worker(s) per node: {self.workers} worker(s)\n'
#             f' Collocate primary and workers: {self.collocate}\n'
#             f' Input rate: {sum(self.rate):,} tx/s\n'
#             f' Transaction size: {self.size[0]:,} B\n'
#             f' Execution time: {round(duration):,} s\n'
#             '\n'
#             #f' Timeout delay: {timeout_delay:,} ms\n'
#             f' Header size: {header_size:,} B\n'
#             f' Max header delay: {max_header_delay:,} ms\n'
#             f' GC depth: {gc_depth:,} round(s)\n'
#             f' Sync retry delay: {sync_retry_delay:,} ms\n'
#             f' Sync retry nodes: {sync_retry_nodes:,} node(s)\n'
#             f' batch size: {batch_size:,} B\n'
#             f' Max batch delay: {max_batch_delay:,} ms\n'
#             '\n'
#             ' + RESULTS:\n'
#             f' Consensus TPS: {round(consensus_tps):,} tx/s\n'
#             f' Consensus BPS: {round(consensus_bps):,} B/s\n'
#             f' Consensus latency: {round(consensus_latency):,} ms\n'
#             '\n'
#             f' End-to-end TPS: {round(end_to_end_tps):,} tx/s\n'
#             f' End-to-end BPS: {round(end_to_end_bps):,} B/s\n'
#             f' End-to-end latency: {round(end_to_end_latency):,} ms\n'
#             '\n'
#             f' Client latency: {round(end_to_end_latency):,} ms\n'
#             '-----------------------------------------\n'
#         )

#     def print(self, filename):
#         assert isinstance(filename, str)
#         with open(filename, 'a') as f:
#             f.write(self.result())

#     @classmethod
#     def process(cls, directory, faults=0):
#         assert isinstance(directory, str)

#         clients = []
#         for filename in sorted(glob(join(directory, 'client*.log'))):
#             print(filename)
#             with open(filename, 'r') as f:
#                 clients += [f.read()]
#         primaries = []
#         for filename in sorted(glob(join(directory, 'primary*.log'))):
#             with open(filename, 'r') as f:
#                 primaries += [f.read()]
#         workers = []
#         for filename in sorted(glob(join(directory, 'worker*.log'))):
#             with open(filename, 'r') as f:
#                 workers += [f.read()]

#         return cls(clients, primaries, workers, faults=faults)

class Color:
    HEADER = '\033[95m'
    OK_BLUE = '\033[94m'
    OK_GREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    END = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

class Print:
    @staticmethod
    def heading(message):
        assert isinstance(message, str)
        print(f'{Color.OK_GREEN}{message}{Color.END}')

    @staticmethod
    def info(message):
        assert isinstance(message, str)
        print(message)

    @staticmethod
    def warn(message):
        assert isinstance(message, str)
        print(f'{Color.BOLD}{Color.WARNING}WARN{Color.END}: {message}')

    @staticmethod
    def error(e):
        # assert isinstance(e, BenchError)
        print(f'\n{Color.BOLD}{Color.FAIL}ERROR{Color.END}: {e}\n')
        causes, current_cause = [], e.cause
        # while isinstance(current_cause, BenchError):
        #     causes += [f'  {len(causes)}: {e.cause}\n']
        #     current_cause = current_cause.cause
        causes += [f'  {len(causes)}: {type(current_cause)}\n']
        causes += [f'  {len(causes)}: {current_cause}\n']
        print(f'Caused by: \n{"".join(causes)}\n')


class ParseError(Exception):
    pass


class ClientMetricsData:
    """Structured metrics extracted from the per-client metrics file using pandas."""

    def __init__(self, client_id, df):
        self.client_id = client_id
        self.df = df

    @classmethod
    def from_file(cls, path):
        try:
            # Read CSV with optimized dtypes
            df = pd.read_csv(
                path,
                dtype={
                    'client_id': 'uint8',
                    'tx_id': 'uint64',
                    'is_sample': 'uint8',
                    'send_ns': 'uint64',
                    'commit_ns': 'uint64',
                    'latency_ns': 'uint64'
                },
                engine='c'
            )

            if df.empty:
                return None

            # Ensure we keep the earliest commit per (client_id, tx_id)
            df = df.sort_values(['commit_ns', 'send_ns'])
            before = len(df)
            df = df.drop_duplicates(subset=['client_id', 'tx_id'], keep='first')
            df.attrs['dedup_dropped'] = before - len(df)

            # Vectorized time conversion from nanoseconds to seconds
            df['send_time'] = df['send_ns'] / 1_000_000_000.0
            df['commit_time'] = df['commit_ns'] / 1_000_000_000.0

            client_id = int(df['client_id'].iloc[0])
            return cls(client_id, df)

        except (OSError, pd.errors.EmptyDataError, KeyError):
            return None


class LogParser:
    def __init__(
        self,
        clients,
        primaries,
        workers,
        metrics_map,
        metrics_by_file=None,
        faults=0,
        parameters=None,
        committee=None,
        client_files=None,
        warmup_seconds=0,
        cooldown_seconds=0,
    ):
        assert isinstance(clients, list) and all(isinstance(x, str) for x in clients)
        assert isinstance(primaries, list) and all(isinstance(x, str) for x in primaries)
        assert isinstance(workers, list) and all(isinstance(x, str) for x in workers)

        self.metrics_map = metrics_map or {}
        self.metrics_by_file = metrics_by_file or {}
        self.faults = faults
        self.parameters = parameters or {}
        self.committee = committee or {}
        self.client_files = [Path(p) for p in (client_files or [])]
        try:
            self.latency_warmup = max(0.0, float(warmup_seconds))
            self.latency_cooldown = max(0.0, float(cooldown_seconds))
        except (TypeError, ValueError):
            raise ParseError('Invalid warmup/cooldown durations')

        if self.committee:
            authorities = self.committee.get('authorities', {})
            self.committee_size = len(authorities)
            if authorities:
                first = next(iter(authorities.values()))
                self.workers = len(first.get('workers', {}))
            else:
                self.workers = '?'
        else:
            if isinstance(faults, int):
                self.committee_size = len(primaries) + int(faults)
                self.workers = len(workers) // len(primaries) if primaries else '?'
            else:
                self.committee_size = '?'
                self.workers = '?'

        # Parse the clients. Prefer metrics files when available to avoid heavy log parsing.
        client_results = []
        missing = []
        for idx, log in enumerate(clients):
            client_path = self.client_files[idx] if idx < len(self.client_files) else None
            result = self._parse_clients_from_metrics(log, client_path)
            if result is None:
                name = (
                    self.client_files[idx].name
                    if idx < len(self.client_files)
                    else f"client-{idx}"
                )
                missing.append(name)
            client_results.append(result)

        if missing:
            names = ', '.join(missing)
            raise ParseError(f'Metrics file missing for client log(s): {names}')

        # Pure pandas implementation - only store essential metadata
        (
            self.size,
            self.rate,
            self.start,
            misses,
        ) = zip(*client_results)
        self.misses = sum(misses)

        # Aggregate using metrics files (required).
        if not self.metrics_map and self.metrics_by_file:
            for data in self.metrics_by_file.values():
                self.metrics_map.setdefault(data.client_id, data)

        if not self.metrics_map:
            raise ParseError('Metrics files are required for client aggregation')

        total_dedup = 0

        # Concatenate all client DataFrames for efficient processing
        all_dfs = []
        for data in self.metrics_map.values():
            if data.df is not None and not data.df.empty:
                total_dedup += data.df.attrs.get('dedup_dropped', 0)
                all_dfs.append(data.df)

        if total_dedup:
            Print.warn(f'Dropped {total_dedup:,} duplicate commits while loading metrics')

        if all_dfs:
            self.all_metrics_df = pd.concat(all_dfs, ignore_index=True)

            # Validate no duplicate transactions - each (client_id, tx_id) should be unique
            duplicates = self.all_metrics_df.duplicated(subset=['client_id', 'tx_id'], keep=False)
            if duplicates.any():
                dup_count = duplicates.sum()
                dup_samples = self.all_metrics_df[duplicates][['client_id', 'tx_id']].head(10)
                Print.warn(f'Found {dup_count} duplicate transactions! Sample: {dup_samples.values.tolist()}')
        else:
            self.all_metrics_df = pd.DataFrame()

        # NOTE: Primaries/workers parsing is disabled; use provided parameters instead.
        self.proposals = {}
        self.commits = {}
        self.configs = [{
            'header_size': self.parameters.get('header_size', 0),
            'max_header_delay': self.parameters.get('max_header_delay', 0),
            'gc_depth': self.parameters.get('gc_depth', 0),
            'sync_retry_delay': self.parameters.get('sync_retry_delay', 0),
            'sync_retry_nodes': self.parameters.get('sync_retry_nodes', 0),
            'batch_size': self.parameters.get('batch_size', 0),
            'max_batch_delay': self.parameters.get('max_batch_delay', 0),
        }]
        self.collocate = self._compute_collocate_from_committee()
        self.sizes = {}

        # Check whether clients missed their target rate.
        if self.misses != 0:
            Print.warn(
                f'Clients missed their target rate {self.misses:,} time(s)'
            )

    def _merge_results(self, input):
        # Keep the earliest timestamp.
        merged = {}
        for x in input:
            for k, v in x:
                if not k in merged or merged[k] > v:
                    merged[k] = v
        return merged
    
    def _compute_collocate_from_committee(self):
        authorities = self.committee.get('authorities', {})
        if not authorities:
            return False

        for info in authorities.values():
            primary_addr = info.get('primary', {}).get('primary_to_primary')
            if not primary_addr:
                return False
            primary_ip = primary_addr.split(':')[0]

            workers = info.get('workers', {})
            for worker_info in workers.values():
                tx_addr = worker_info.get('transactions')
                if not tx_addr:
                    return False
                worker_ip = tx_addr.split(':')[0]
                if worker_ip != primary_ip:
                    return False
        return True
    
    def _parse_clients_from_metrics(self, log, client_path=None):
        size_match = search(r'Transactions size: (\d+)', log)
        size = int(size_match.group(1)) if size_match else 0
        rate_match = search(r'Transactions rate: (\d+)', log)
        rate = int(rate_match.group(1)) if rate_match else 0
        misses = len(findall(r'rate too high', log))

        client_match = search(r'Client (\d+) Start sending transactions', log)
        if client_match is None:
            client_match = search(r'Client (\d+) sending sample transaction', log)
        if client_match is None:
            client_match = search(r'Client (\d+) successfully started', log)
        client_id = int(client_match.group(1)) if client_match else None

        metrics_entry = None
        if client_id is not None:
            metrics_entry = self.metrics_map.get(client_id)
        if metrics_entry is None and client_path is not None:
            metrics_entry = self.metrics_by_file.get(client_path.name)
        if metrics_entry is None and client_path is not None:
            metrics_entry = ClientMetricsData.from_file(client_path.with_suffix('.metrics'))
            if metrics_entry is not None:
                self.metrics_map.setdefault(metrics_entry.client_id, metrics_entry)
                self.metrics_by_file.setdefault(client_path.name, metrics_entry)
        if metrics_entry is None:
            return None

        # Pure pandas implementation - only return essential metadata
        start = metrics_entry.df['send_time'].min() if not metrics_entry.df.empty else 0
        return size, rate, start, misses

    def _parse_clients(self, log):
        if search(r'Error', log) is not None:
            raise ParseError('Client(s) panicked')

        size_match = search(r'Transactions size: (\d+)', log)
        size = int(size_match.group(1)) if size_match else 0
        rate_match = search(r'Transactions rate: (\d+)', log)
        rate = int(rate_match.group(1)) if rate_match else 0

        start_match = search(r'\[(.*Z) .* Start ', log)
        start = self._to_posix(start_match.group(1)) if start_match else 0

        misses = len(findall(r'rate too high', log))

        client_match = search(r'Client (\d+) Start sending transactions', log)
        if client_match is None:
            client_match = search(r'Client (\d+) sending sample transaction', log)
        if client_match is None:
            client_match = search(r'Client (\d+) successfully started', log)
        client_id = int(client_match.group(1)) if client_match else None

        if client_id is not None:
            metrics_entry = self.metrics_map.get(client_id)
            if metrics_entry:
                # Pandas-only implementation - fallback not supported
                raise ParseError('Fallback parsing from logs not supported - metrics files required')

        # Old regex-based parsing - not supported anymore
        raise ParseError('Fallback parsing from logs not supported - metrics files required')

    def _parse_primaries(self, log):
        if search(r'(?:panicked|Error)', log) is not None:
            raise ParseError('Primary(s) panicked')

        tmp = findall(r'\[(.*Z) .* Created B\d+\([^ ]+\) -> ([^ ]+=)', log)
        tmp = [(d, self._to_posix(t)) for t, d in tmp]
        proposals = self._merge_results([tmp])

        tmp = findall(r'\[(.*Z) .* Committed B\d+\([^ ]+\) -> ([^ ]+=)', log)
        tmp = [(d, self._to_posix(t)) for t, d in tmp]
        commits = self._merge_results([tmp])

        configs = {
            #'timeout_delay': int(
            #    search(r'Timeout delay .* (\d+)', log).group(1)
            #),
            'header_size': int(
                search(r'Header size .* (\d+)', log).group(1)
            ),
            'max_header_delay': int(
                search(r'Max header delay .* (\d+)', log).group(1)
            ),
            'gc_depth': int(
                search(r'Garbage collection depth .* (\d+)', log).group(1)
            ),
            'sync_retry_delay': int(
                search(r'Sync retry delay .* (\d+)', log).group(1)
            ),
            'sync_retry_nodes': int(
                search(r'Sync retry nodes .* (\d+)', log).group(1)
            ),
            'batch_size': int(
                search(r'Batch size .* (\d+)', log).group(1)
            ),
            'max_batch_delay': int(
                search(r'Max batch delay .* (\d+)', log).group(1)
            ),
        }

        ip = search(r'booted on (\d+.\d+.\d+.\d+)', log).group(1)

        return proposals, commits, configs, ip

    def _parse_workers(self, log):
        if search(r'(?:panic|Error)', log) is not None:
            raise ParseError('Worker(s) panicked')

        tmp = findall(r'Batch ([^ ]+) contains (\d+) B', log)
        sizes = {d: int(s) for d, s in tmp}

        ip = search(r'booted on (\d+.\d+.\d+.\d+)', log).group(1)

        return sizes, ip

    def _to_posix(self, string):
        x = datetime.fromisoformat(string.replace('Z', '+00:00'))
        return datetime.timestamp(x)

    def _consensus_latency(self):
        latency = [c - self.proposals[d] for d, c in self.commits.items()]
        return mean(latency) if latency else 0

    def _per_client_throughput(self):
        """Compute throughput by summing per-client contributions using vectorized operations."""
        if not self.metrics_map or not self.size:
            return 0, 0, 0

        size_bytes = self.size[0]
        total_tps = 0.0
        total_bps = 0.0
        durations = []

        for data in self.metrics_map.values():
            if data.df is None or data.df.empty:
                continue

            # Vectorized operations on DataFrame
            df = data.df
            start = df['send_time'].min()
            end = df['commit_time'].max()
            duration = end - start

            if duration <= 0:
                continue

            tx_count = len(df)
            client_tps = tx_count / duration
            client_bps = (tx_count * size_bytes) / duration

            total_tps += client_tps
            total_bps += client_bps
            durations.append(duration)

        overall_duration = max(durations) if durations else 0
        return total_tps, total_bps, overall_duration

    def _end_to_end_throughput(self):
        return self._per_client_throughput()

    def _end_to_end_latency(self):
        """Compute end-to-end latency using vectorized pandas operations."""
        if self.all_metrics_df.empty:
            return {'mean': 0, 'p50': 0, 'p95': 0, 'p99': 0, 'p999': 0}

        df = self.all_metrics_df.copy()

        # Vectorized latency calculation
        df['latency'] = df['commit_time'] - df['send_time']

        # Track totals before trimming
        total_samples = int(df['is_sample'].sum())
        total_transactions = len(df)
        first_send = df['send_time'].min()
        last_commit = df['commit_time'].max()

        # Apply warmup/cooldown trimming
        lower_bound = None
        upper_bound = None
        if self.latency_warmup > 0:
            lower_bound = first_send + self.latency_warmup
        if self.latency_cooldown > 0:
            upper_bound = last_commit - self.latency_cooldown
        if lower_bound is not None and upper_bound is not None and upper_bound <= lower_bound:
            lower_bound = upper_bound = None

        # Vectorized filtering
        original_len = len(df)
        if lower_bound is not None:
            df = df[df['send_time'] >= lower_bound]
        if upper_bound is not None:
            df = df[df['commit_time'] <= upper_bound]

        trimmed_transactions = original_len - len(df)
        trimmed_samples = total_samples - int(df['is_sample'].sum())

        # Handle case where all transactions were trimmed
        if df.empty and original_len > 0:
            Print.warn('Warmup/cooldown trimming removed all transaction latencies; recomputing without trimming.')
            df = self.all_metrics_df.copy()
            df['latency'] = df['commit_time'] - df['send_time']
            trimmed_samples = 0
            trimmed_transactions = 0

        # Write latencies.txt for sample transactions
        sample_df = df[df['is_sample'] == 1].copy()
        if not sample_df.empty:
            first_start = sample_df['send_time'].min()
            sample_df['start_offset'] = sample_df['send_time'] - first_start
            sample_df['commit_offset'] = sample_df['commit_time'] - first_start
            sample_df = sample_df.sort_values('start_offset')
            sample_df[['start_offset', 'commit_offset', 'latency']].to_csv(
                'latencies.txt', index=False, header=False
            )
        else:
            # Write empty file if no samples
            with open('latencies.txt', 'w') as f:
                pass

        print('Num sent samples:', total_samples, 'Trimmed:', trimmed_samples)
        print('Num sent transactions:', total_transactions, 'Trimmed:', trimmed_transactions)
        print('Num sample latencies:', int(df['is_sample'].sum()))
        print('Num all latencies:', len(df))

        if df.empty:
            return {'mean': 0, 'p50': 0, 'p95': 0, 'p99': 0, 'p999': 0}

        # Vectorized percentile calculations
        latencies = df['latency'].values
        mean_latency = float(latencies.mean())
        p50 = float(np.percentile(latencies, 50))
        p95 = float(np.percentile(latencies, 95))
        p99 = float(np.percentile(latencies, 99))
        p999 = float(np.percentile(latencies, 99.9))

        return {
            'mean': mean_latency,
            'p50': p50,
            'p95': p95,
            'p99': p99,
            'p999': p999
        }

    def result(self):
        #timeout_delay = self.configs[0]['timeout_delay']
        header_size = self.configs[0]['header_size']
        max_header_delay = self.configs[0]['max_header_delay']
        gc_depth = self.configs[0]['gc_depth']
        sync_retry_delay = self.configs[0]['sync_retry_delay']
        sync_retry_nodes = self.configs[0]['sync_retry_nodes']
        batch_size = self.configs[0]['batch_size']
        max_batch_delay = self.configs[0]['max_batch_delay']

        end_to_end_tps, end_to_end_bps, duration = self._end_to_end_throughput()
        latency_stats = self._end_to_end_latency()
        end_to_end_latency = latency_stats['mean'] * 1_000
        end_to_end_p50 = latency_stats['p50'] * 1_000
        end_to_end_p95 = latency_stats['p95'] * 1_000
        end_to_end_p99 = latency_stats['p99'] * 1_000
        end_to_end_p999 = latency_stats['p999'] * 1_000

        return (
            '\n'
            '-----------------------------------------\n'
            ' SUMMARY:\n'
            '-----------------------------------------\n'
            ' + CONFIG:\n'
            f' Faults: {self.faults} node(s)\n'
            f' Committee size: {self.committee_size} node(s)\n'
            f' Worker(s) per node: {self.workers} worker(s)\n'
            f' Collocate primary and workers: {self.collocate}\n'
            f' Input rate: {sum(self.rate):,} tx/s\n'
            f' Transaction size: {self.size[0]:,} B\n'
            f' Execution time: {round(duration):,} s\n'
            '\n'
            #f' Timeout delay: {timeout_delay:,} ms\n'
            f' Header size: {header_size:,} B\n'
            f' Max header delay: {max_header_delay:,} ms\n'
            f' GC depth: {gc_depth:,} round(s)\n'
            f' Sync retry delay: {sync_retry_delay:,} ms\n'
            f' Sync retry nodes: {sync_retry_nodes:,} node(s)\n'
            f' batch size: {batch_size:,} B\n'
            f' Max batch delay: {max_batch_delay:,} ms\n'
            '\n'
            ' + RESULTS:\n'
            #f' Consensus TPS: {round(consensus_tps):,} tx/s\n'
            #f' Consensus BPS: {round(consensus_bps):,} B/s\n'
            #f' Consensus latency: {round(consensus_latency):,} ms\n'
            f' End-to-end TPS: {round(end_to_end_tps):,} tx/s\n'
            f' End-to-end BPS: {round(end_to_end_bps):,} B/s\n'
            f' End-to-end latency (mean): {round(end_to_end_latency):,} ms\n'
            f' End-to-end latency (P50): {round(end_to_end_p50):,} ms\n'
            f' End-to-end latency (P95): {round(end_to_end_p95):,} ms\n'
            f' End-to-end latency (P99): {round(end_to_end_p99):,} ms\n'
            f' End-to-end latency (P99.9): {round(end_to_end_p999):,} ms\n'
            '-----------------------------------------\n'
        )

    def print(self, filename):
        assert isinstance(filename, str)
        with open(filename, 'a') as f:
            f.write(self.result())

    @classmethod
    def process(cls, directory, faults=0, warmup_seconds=0, cooldown_seconds=0):
        assert isinstance(directory, str)

        client_files = sorted(glob(join(directory, 'client*.log')))
        print(client_files)
        clients = [Path(path).read_text() for path in client_files]
        primaries = []
        workers = []

        directory_path = Path(directory)
        root = directory_path.parent
        params_path = root / '.parameters.json'
        committee_path = root / '.committee.json'

        parameters = {}
        committee = {}
        if params_path.exists():
            parameters = json.loads(params_path.read_text())
        if committee_path.exists():
            committee = json.loads(committee_path.read_text())

        metrics_map, metrics_by_file = cls._load_metrics(client_files)

        return cls(
            clients,
            primaries,
            workers,
            metrics_map,
            metrics_by_file=metrics_by_file,
            faults=faults,
            parameters=parameters,
            committee=committee,
            client_files=client_files,
            warmup_seconds=warmup_seconds,
            cooldown_seconds=cooldown_seconds,
        )

    @staticmethod
    def _load_metrics(client_files):
        metrics_by_id = {}
        metrics_by_file = {}
        for log_path in client_files:
            log_path = Path(log_path)
            metrics_path = log_path.with_suffix('.metrics')
            data = ClientMetricsData.from_file(metrics_path)
            if data is not None:
                metrics_by_id[data.client_id] = data
                metrics_by_file[log_path.name] = data
        return metrics_by_id, metrics_by_file
