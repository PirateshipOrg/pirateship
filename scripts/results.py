
import collections
from copy import deepcopy
from dataclasses import dataclass
import json
import os
import pickle
from statistics import mean
from typing import Callable, Dict, List, OrderedDict, Tuple

from experiments import BaseExperiment
from collections import defaultdict
import re
from dateutil.parser import isoparse
import datetime
import numpy as np
from pprint import pprint
import matplotlib
import matplotlib.pyplot as plt
import pandas as pd

plt.rc('font',**{'size': 100, 'family':'serif','serif':['Linux Libertine O']})
# plt.rc('legend', fontsize=7)
# plt.rc('figure', figsize=sizeFig)
# plt.rc('axes', linewidth=0.5)
# plt.rc('lines', linewidth=0.5)
matplotlib.rcParams['ps.useafm'] = True
matplotlib.rcParams['pdf.use14corefonts'] = True
matplotlib.rcParams['text.usetex'] = True
# matplotlib.rcParams["text.latex.preview"] = True
matplotlib.rcParams['text.latex.preamble'] = r"""
\usepackage{libertine}
\usepackage[libertine]{newtxmath}
"""

from autobahn_logs import LogParser as AutobahnLogParser
from autobahn_experiments import AutobahnExperiment

# Log format follows the log4rs config.
# Capture the time from the 3rd []

# Sample log: [INFO][pft::execution::engines::logger][2024-08-06T10:28:13.926997933+00:00] fork.last = 2172, fork.last_qc = 2169, commit_index = 2171, byz_commit_index = 2166, pending_acks = 200, pending_qcs = 1 num_crash_committed_txs = 100, num_byz_committed_txs = 100, fork.last_hash = b7da989badce213929ab457e5301b587593e0781e081ba7261d57cd7778e1b7b, total_client_request = 388706, view = 1, view_is_stable = true, i_am_leader: true
node_rgx = re.compile(r"\[INFO\]\[.*\]\[(.*)\] fork\.last = ([0-9]+), fork\.last_qc = ([0-9]+), commit_index = ([0-9]+), byz_commit_index = ([0-9]+), pending_acks = ([0-9]+), pending_qcs = ([0-9]+) num_crash_committed_txs = ([0-9]+), num_byz_committed_txs = ([0-9]+), fork\.last_hash = (.+), total_client_request = ([0-9]+), view = ([0-9]+), view_is_stable = (.+), i_am_leader\: (.+)")
node_rgx2 = re.compile(r"\[INFO\]\[.*\]\[(.*)\] Total unlogged txs: ([0-9]+)")

# Sample log: [INFO][pft::client::logger][2025-02-25T23:33:23.145307984+00:00] Average Crash commit latency: 104390 us, Average Byz commit latency: 29271247 us
client_rgx = re.compile(r"\[INFO\]\[.*\]\[(.*)\] Average Crash commit latency: ([0-9]+) us, Average Byz commit latency: ([0-9]+) us")


def process_tput(points, duration, ramp_up, ramp_down, tputs, tputs_unbatched, byz=False, read_points=[[]]) -> List:
    '''
    Parses given points for throughput information.
    Skipping points before ramp_up and after ramp_down.
    Returns the filtered points.
    '''
    points = [
        (
            isoparse(a[0]),    # 0: ISO format is used in run_remote
            int(a[1]),         # 1: fork.last
            int(a[2]),         # 2: fork.last_qc
            int(a[3]),         # 3: commit_index
            int(a[4]),         # 4: byz_commit_index
            int(a[5]),         # 5: pending_acks
            int(a[6]),         # 6: pending_qcs
            int(a[7]),         # 7: num_crash_txs,
            int(a[8]),         # 8: num_byz_txs,
            a[9],              # 9: fork.last_hash,
            int(a[10]),        # 10: total_client_request
            int(a[11]),        # 11: view
            a[12] == "true",   # 12: view_is_stable
            a[13] == "true"    # 13: i_am_leader
        )
        for a in points
    ]

    read_points = [
        [
            (
                isoparse(a[0]),
                int(a[1])
            )
            for a in _rp
        ]
        for _rp in read_points
    ]

    # Filter points, only keep if after ramp_up time and before ramp_down time

    start_time = points[0][0] + datetime.timedelta(seconds=ramp_up)
    end_time = points[0][0] + datetime.timedelta(seconds=duration) - datetime.timedelta(seconds=ramp_down)

    points = [p for p in points if p[0] >= start_time and p[0] <= end_time]
    read_points = [
        [p for p in _rp if p[0] >= start_time and p[0] <= end_time]
        for _rp in read_points
    ]

    total_runtime = (points[-1][0] - points[0][0]).total_seconds()
    if byz:
        total_commit = points[-1][4] - points[0][4]
        total_tx = points[-1][8] - points[0][8]
    else:
        total_commit = points[-1][3] - points[0][3]
        total_tx = points[-1][7] - points[0][7]
    
    total_reads = 0

    for _rp in read_points:
        if len(_rp) > 0:
            total_reads += _rp[-1][1] - _rp[0][1]
    
    total_tx += total_reads

    print(total_commit, total_tx, total_runtime)

    tputs.append(total_tx / total_runtime)
    tputs_unbatched.append(total_commit / total_runtime)

    return points


def process_latencies(points, duration, ramp_up, ramp_down, latencies, byz=False):
    points = [
        (
            isoparse(a[0]),      # ISO format is used in run_remote
            float(a[1]),         # Crash commit latency
            float(a[2])          # Byz commit latency
        )
        for a in points
    ]
    
    total_n = len(points)

    # Filter points, only keep if after ramp_up time and before ramp_down time

    start_time = points[0][0] + datetime.timedelta(seconds=ramp_up)
    end_time = points[0][0] + datetime.timedelta(seconds=duration) - datetime.timedelta(seconds=ramp_down)

    points = [p for p in points if p[0] >= start_time and p[0] <= end_time]

    if byz:
        latencies.extend([p[2] for p in points])
    else:
        latencies.extend([p[1] for p in points])

RESOURCE_TYPES = ['cpu', 'memory', 'net_recv', 'net_send', 'disk_read', 'disk_write']
def parse_stats_file(file_path: str, duration: int, ramp_up: int, ramp_down: int):
    """Parse a single dool stats CSV file."""
    try:
        df = pd.read_csv(file_path, skiprows=5)
        if len(df) == 0:
            return None
        
        if duration > 0:
            start_idx = ramp_up
            end_idx = duration - ramp_down
            if end_idx > len(df):
                end_idx = len(df)
            df = df[start_idx:end_idx]
        
        time_indices = list(range(len(df)))
        
        resources = {}
        
        # CPU: usr + sys
        if 'usr' in df.columns and 'sys' in df.columns:
            usr = pd.to_numeric(df['usr'], errors='coerce').fillna(0)
            sys = pd.to_numeric(df['sys'], errors='coerce').fillna(0)
            resources['cpu'] = list(zip(time_indices, usr + sys))
        
        # Memory usage (convert to MB)
        if 'used' in df.columns:
            mem = pd.to_numeric(df['used'], errors='coerce').fillna(0) / (1024*1024)
            resources['memory'] = list(zip(time_indices, mem))
        
        # Network (convert to MB/s)
        if 'recv' in df.columns:
            net_recv = pd.to_numeric(df['recv'], errors='coerce').fillna(0) / (1024*1024)
            resources['net_recv'] = list(zip(time_indices, net_recv))
        
        if 'send' in df.columns:
            net_send = pd.to_numeric(df['send'], errors='coerce').fillna(0) / (1024*1024)
            resources['net_send'] = list(zip(time_indices, net_send))
        
        # Disk I/O (convert to MB/s)
        if 'read' in df.columns:
            disk_read = pd.to_numeric(df['read'], errors='coerce').fillna(0) / (1024*1024)
            resources['disk_read'] = list(zip(time_indices, disk_read))
        
        if 'writ' in df.columns:
            disk_write = pd.to_numeric(df['writ'], errors='coerce').fillna(0) / (1024*1024)
            resources['disk_write'] = list(zip(time_indices, disk_write))
        
        return resources
        
    except Exception as e:
        print(f"Error parsing {file_path}: {e}")
        return None


@dataclass
class Stats:
    num_nodes: int
    num_clients: int
    mean_tput: float
    stdev_tput: float
    mean_tput_unbatched: float
    stdev_tput_unbatched: float
    latency_prob_dist: List[float]
    mean_latency: float
    median_latency: float
    p25_latency: float
    p75_latency: float
    p99_latency: float
    max_latency: float
    min_latency: float
    stdev_latency: float


@dataclass
class Result:
    name: str
    plotter_func: Callable
    experiment_groups: Dict[str, List[BaseExperiment]]
    workdir: str
    kwargs: dict


    def default_output(self):
        print(f"Default output method: {self}")

    def parse_node_logs(self, log_dir, node_log_names, duration, ramp_up, ramp_down, tputs, tputs_unbatched, byz=False):
        '''
        Parse node logs for throughput information.
        Only uses the first log to get overall consensus throughput.
        Should there be read operations, uses all logs to get read throughput.

        tputs and tputs_unbatched will be filled.
        Side-effect is the timeseries of points which will be returned.
        '''
        points = []
        read_points = []
        with open(os.path.join(log_dir, node_log_names[0]), "r") as f:
            for line in f.readlines():
                captures = node_rgx.findall(line)
                if len(captures) == 1:
                    points.append(captures[0])

        num_nodes = len(node_log_names)
        for node_num in range(num_nodes):
            _rp = []
            with open(os.path.join(log_dir, node_log_names[node_num]), "r") as f:
                for line in f.readlines():
                    captures = node_rgx2.findall(line)
                    if len(captures) == 1:
                        _rp.append(captures[0])
            read_points.append(_rp)

        try:
            _points = process_tput(points, duration, ramp_up, ramp_down, tputs, tputs_unbatched, byz, read_points)
        except:
            _points = []

        return _points
    

    def parse_client_logs(self, log_dir, client_log_names, duration, ramp_up, ramp_down, latencies, byz=False):
        points = []
        for log_name in client_log_names:
            fname = os.path.join(log_dir, log_name)
            try:
                with open(fname, "r") as f:
                    for line in f.readlines():
                        captures = client_rgx.findall(line)
                        # print(captures)
                        if len(captures) == 1:
                            points.append(captures[0])
            except:
                pass
        try:
            process_latencies(points, duration, ramp_up, ramp_down, latencies, byz=byz)
        except:
            pass

    def process_experiment(self, experiment, ramp_up, ramp_down, byz, tput_scale=1000.0, latency_scale=1000.0) -> Stats | None:
        tputs = []
        tputs_unbatched = []
        latencies = []
        duration = experiment.duration
        for repeat_num in range(experiment.repeats):
            log_dir = os.path.join(experiment.get_local_workdir(), "logs", str(repeat_num))
            # Find the first node log file and all client log files in log_dir
            node_log_files = list(sorted([f for f in os.listdir(log_dir) if f.startswith("node") and f.endswith(".log")]))
            client_log_files = [f for f in os.listdir(log_dir) if f.startswith("client") and f.endswith(".log")]

            self.parse_node_logs(log_dir, node_log_files, duration, ramp_up, ramp_down, tputs, tputs_unbatched, byz=byz)
            self.parse_client_logs(log_dir, client_log_files, duration, ramp_up, ramp_down, latencies, byz=byz)
        print(len(tputs), len(tputs_unbatched), len(latencies))
        if len(latencies) == 0:
            return None
        latency_prob_dist = np.array(latencies)
        latency_prob_dist.sort()
        # latency_prob_dist = latency_prob_dist.clip(latency_prob_dist[0], quantiles(latencies, n=100)[98])
        p = 1. * np.arange(len(latency_prob_dist)) / (len(latency_prob_dist) - 1)
        try:
            stdev_tput = np.std(tputs)
        except:
            stdev_tput = 0
        
        try:
            stdev_tput_unbatched = np.std(tputs_unbatched)
        except:
            stdev_tput_unbatched = 0
        
        try:
            stdev_latency = np.std(latencies)
        except:
            stdev_latency = 0

        mean_latency = np.mean(latencies)

        try:
            median_latency = np.median(latencies)
            p25_latency=np.percentile(latencies, 25),
            p75_latency=np.percentile(latencies, 75),
            p99_latency=np.percentile(latencies, 99),
        except:
            median_latency = mean_latency
            p25_latency = mean_latency
            p75_latency = mean_latency
            p99_latency = mean_latency

        ret = Stats(
            num_nodes=experiment.num_nodes,
            num_clients=experiment.num_clients,
            mean_tput=np.mean(tputs),
            stdev_tput=stdev_tput,
            mean_tput_unbatched=np.mean(tputs_unbatched),
            stdev_tput_unbatched=stdev_tput_unbatched,
            latency_prob_dist=latency_prob_dist,
            mean_latency=mean_latency,
            median_latency=median_latency,
            p25_latency=p25_latency,
            p75_latency=p75_latency,
            p99_latency=p99_latency,
            max_latency=np.max(latencies),
            min_latency=np.min(latencies),
            stdev_latency=stdev_latency
        )

        for k, v in ret.__dict__.items():
            if "tput" in k and isinstance(v, float):
                ret.__dict__[k] /= tput_scale
            if "latency" in k and isinstance(v, float):
                ret.__dict__[k] /= latency_scale

        return ret


    def process_autobahn_experiment(self, experiment, ramp_up, ramp_down, byz, tput_scale=1000.0, latency_scale=1.0) -> Stats | None:
        """
        For autobahn, we only take the first repeat.
        """
        log_dir = os.path.join(experiment.get_local_workdir(), "logs", "0")
        print(log_dir)
        try:
            result = AutobahnLogParser.process(log_dir).result()
            mean_tput = 0.0
            mean_latency = 0.0
            for line in result.split("\n"):
                print(line)
                if line.startswith(" Consensus TPS"):
                    mean_tput = line.split(":")[-1].strip()
                    mean_tput = mean_tput.replace(",", "")
                    mean_tput = float(mean_tput.split(" ")[0]) / tput_scale

                if line.startswith(" Client latency"):
                    mean_latency = line.split(":")[-1].strip()
                    mean_latency = mean_latency.replace(",", "")
                    mean_latency = float(mean_latency.split(" ")[0]) / latency_scale

            return Stats(
                num_nodes=experiment.num_nodes,
                num_clients=experiment.num_clients,
                mean_tput=mean_tput,
                stdev_tput=0,
                mean_tput_unbatched=0,
                stdev_tput_unbatched=0,
                latency_prob_dist=[],
                mean_latency=mean_latency,
                median_latency=mean_latency,
                p25_latency=mean_latency,
                p75_latency=mean_latency,
                p99_latency=mean_latency,
                max_latency=mean_latency,
                min_latency=mean_latency,
                stdev_latency=0
            )
        except Exception as e:
            print(e)
            return None

    def tput_latency_sweep_parse(self, ramp_up, ramp_down, legends) -> Dict[str, List[Stats]]:
        plot_dict = {}

        # Which indices do I skip?
        skip_indices = self.kwargs.get('skip_indices', [])

        # Find parsing log files for each group
        for group_name, experiments in self.experiment_groups.items():
            print("========", group_name, "========")
            experiments.sort(key=lambda x: x.seq_num)
            crash_legend = None
            byz_legend = None
            legend = legends.get(group_name, None)
            if legend is None:
                print("\x1b[31;1mNo legend found for", group_name, ". Skipping...\x1b[0m")
                continue

            if "+byz" in legend:
                needs_byz = True
                needs_crash = True
                names = legend.split("+")
                _legend = names[0]
                crash_legend = _legend[:]
                if len(names) == 2:
                    byz_legend = _legend[:] + "-byz"
                else:
                    byz_legend = names[1]
            elif "+onlybyz" in legend:
                needs_byz = True
                needs_crash = False
                _legend = legend.replace("+onlybyz", "")
                byz_legend = _legend[:]
            else:
                needs_byz = False
                needs_crash = True
                crash_legend = legend[:]
            
            if needs_crash:
                final_stats = []

                for idx, experiment in enumerate(experiments):
                    if idx in skip_indices:
                        print("\x1b[31;1mSkipping experiment", experiment.name, "for crash commit\x1b[0m")
                        continue

                    if isinstance(experiment, AutobahnExperiment):
                        experiment_type = "autobahn"
                    else:
                        experiment_type = "pirateship"

                    if experiment_type == "pirateship":
                        stats = self.process_experiment(experiment, ramp_up, ramp_down, byz=False)
                    elif experiment_type == "autobahn":
                        stats = self.process_autobahn_experiment(experiment, ramp_up, ramp_down, byz=False)
                    if stats is not None:
                        final_stats.append(stats)
                    else:
                        print("\x1b[31;1mSkipping experiment", experiment.name, "for crash commit\x1b[0m")

                plot_dict[crash_legend] = final_stats
                

            if needs_byz:
                final_stats = []

                for idx, experiment in enumerate(experiments):
                    if idx in skip_indices:
                        print("\x1b[31;1mSkipping experiment", experiment.name, "for byz commit\x1b[0m")
                        continue
                    stats = self.process_experiment(experiment, ramp_up, ramp_down, byz=True)
                    if stats is not None:
                        final_stats.append(stats)
                    else:
                        print("\x1b[31;1mSkipping experiment", experiment.name, "for byz commit\x1b[0m")

                plot_dict[byz_legend] = final_stats

        pprint(plot_dict)
        return plot_dict
    

    def tput_latency_prepare_plot(self, fig, axes, x_ranges, y_ranges, is_1d, legends_ncols, total_x_axes, total_y_axes):
        if is_1d:
            axes[0].set_xlabel("Throughput (k req/s)")
            axes[0].set_ylabel("Latency (ms)")
            axes[0].yaxis.set_label_coords(0.04, 0.5, transform=fig.transFigure)
            axes[0].xaxis.set_label_coords(0.5, 0.05, transform=fig.transFigure)
            axes[0].legend(loc='upper center', bbox_to_anchor=(0.5, 1.45), ncol=legends_ncols, fontsize=55, columnspacing=1)
        else:
            axes[0, 0].set_xlabel("Throughput (k req/s)")
            axes[0, 0].set_ylabel("Latency (ms)")
            axes[0, 0].yaxis.set_label_coords(0.04, 0.5, transform=fig.transFigure)
            axes[0, 0].xaxis.set_label_coords(0.5, 0.05, transform=fig.transFigure)
            axes[0, 0].legend(loc='upper center', bbox_to_anchor=(0.5, 1.45), ncol=legends_ncols, fontsize=55, columnspacing=1)

        for ax in list(axes.flatten()):
            ax.spines.bottom.set_visible(False)
            ax.spines.top.set_visible(False)
            ax.xaxis.tick_top()
            ax.xaxis.tick_bottom()
            ax.tick_params(labeltop=False, labelbottom=False)
            ax.spines.right.set_visible(False)
            ax.spines.left.set_visible(False)
            ax.yaxis.tick_left()
            ax.yaxis.tick_right()
            ax.tick_params(labelright=False, labelleft=False)

        # Make bottom spine visible for the last row
        for x in range(total_x_axes):
            ycoord = -1
            if is_1d and total_x_axes > 1:
                # ----------
                axes[x].spines.bottom.set_visible(True)
                axes[x].tick_params(labelbottom=True)
            elif is_1d:
                # |
                # |
                # |
                axes[ycoord].spines.bottom.set_visible(True)
                axes[ycoord].tick_params(labelbottom=True)
            else:
                # |||
                # |||
                axes[ycoord, x].spines.bottom.set_visible(True)
                axes[ycoord, x].tick_params(labelbottom=True)

        # Make top spine visible for the first row
        for x in range(total_x_axes):
            ycoord = 0
            if is_1d and total_x_axes > 1:
                # ----------
                axes[x].spines.top.set_visible(True)
                # axes[x].tick_params(labeltop=True)
            elif is_1d:
                # |
                # |
                # |
                axes[ycoord].spines.top.set_visible(True)
                # axes[ycoord].tick_params(labeltop=True)
            else:
                # |||
                # |||
                axes[ycoord, x].spines.top.set_visible(True)
                # axes[ycoord, x].tick_params(labeltop=True)

        # Make left spine visible for the first col
        for y in range(total_y_axes):
            if is_1d and total_y_axes > 1:
                # |
                # |
                # |
                axes[y].spines.left.set_visible(True)
                axes[y].tick_params(labelleft=True)
            elif is_1d:
                # ----------
                axes[0].spines.left.set_visible(True)
                axes[0].tick_params(labelleft=True)
            else:
                # |||
                # |||
                axes[y, 0].spines.left.set_visible(True)
                axes[y, 0].tick_params(labelleft=True)

        # Make right spine visible for the last col
        for y in range(total_y_axes):
            xcoord = -1
            if is_1d and total_y_axes > 1:
                # |
                # |
                # |
                axes[y].spines.right.set_visible(True)
                # axes[y].tick_params(labelright=True)
            elif is_1d:
                # ----------
                axes[xcoord].spines.right.set_visible(True)
                # axes[xcoord].tick_params(labelright=True)
            else:
                # |||
                # |||
                axes[y, xcoord].spines.right.set_visible(True)
                # axes[y, xcoord].tick_params(labelright=True)

        
        d = .5  # proportion of vertical to horizontal extent of the slanted line
        kwargs = dict(marker=[(-1, -d), (1, d)], markersize=12,
                    linestyle="none", color='k', mec='k', mew=1, clip_on=False)
        if is_1d and total_x_axes > 1:
            # ----------
            # Put a \ mark on the right of x-axis for all except the last one
            for x in range(total_x_axes - 1):
                axes[x].plot([1, 1], [1, 0], transform=axes[x].transAxes, **kwargs)
            
            # Put a \ mark on the left of x-axis for all except the first one
            for x in range(1, total_x_axes):
                axes[x].plot([0, 0], [1, 0], transform=axes[x].transAxes, **kwargs)

        elif is_1d:
            # |
            # |
            # |
            # Put a \ mark on the top of y-axis for all except the first one
            for y in range(1, total_y_axes):
                axes[y].plot([0, 1], [1, 1], transform=axes[y].transAxes, **kwargs)

            # Put a \ mark on the bottom of y-axis for all except the last one
            for y in range(total_y_axes - 1):
                axes[y].plot([0, 1], [0, 0], transform=axes[y].transAxes, **kwargs)

        else:
            # |||
            # |||
            for x in range(total_x_axes):
                # Put a \ mark on the top of y-axis for all except the first one
                for y in range(1, total_y_axes):
                    axes[y, x].plot([0, 1], [1, 1], transform=axes[y, x].transAxes, **kwargs)

                # Put a \ mark on the bottom of y-axis for all except the last one
                for y in range(total_y_axes - 1):
                    axes[y, x].plot([0, 1], [0, 0], transform=axes[y, x].transAxes, **kwargs)

            for y in range(total_y_axes):
                # Put a \ mark on the right of x-axis for all except the last one
                for x in range(total_x_axes - 1):
                    axes[y, x].plot([1, 1], [1, 0], transform=axes[y, x].transAxes, **kwargs)
                
                # Put a \ mark on the left of x-axis for all except the first one
                for x in range(1, total_x_axes):
                    axes[y, x].plot([0, 0], [1, 0], transform=axes[y, x].transAxes, **kwargs)
            


        for x in range(total_x_axes):
            for y in range(total_y_axes):
                xlim = x_ranges[x]
                ylim = y_ranges[y]
                ycoord = total_y_axes - y - 1
                xcoord = x

                if total_x_axes == 1:
                    axes[ycoord].set_xlim(xlim)
                    axes[ycoord].set_ylim(ylim)
                elif total_y_axes == 1:
                    axes[xcoord].set_xlim(xlim)
                    axes[xcoord].set_ylim(ylim)
                else:
                    axes[ycoord, xcoord].set_xlim(xlim)
                    axes[ycoord, xcoord].set_ylim(ylim)


    def tput_latency_sweep_plot(self, plot_dict: Dict[str, List[Stats]], output: str | None, logscale: bool = False, xlabel: str = "Throughput (k req/s)", ylabel: str = "Latency (ms)") -> None:
        # Find how many subfigures we need.

        bounding_boxes = {
            k: [
                min([stat.mean_tput for stat in v]),    # Xmin
                max([stat.mean_tput for stat in v]),    # Xmax
                min([stat.mean_latency for stat in v]), # Ymin
                max([stat.mean_latency for stat in v]), # Ymax
            ]
            for k, v in plot_dict.items()
        }


        # Leave padding around bounding boxes
        for k, v in bounding_boxes.items():
            v[0] -= 0.1 * v[0]
            v[1] += 0.1 * v[1]
            v[2] -= 0.1 * v[2]
            v[3] += 0.1 * v[3]
            bounding_boxes[k] = v

        num_x_axis_breaks = 0
        num_y_axis_breaks = 0

        GAP_THRESH = 1.0

        x_sorted_box = list(bounding_boxes.items())
        x_sorted_box.sort(key=lambda x: x[1][0])
        curr_x_cluster = [x_sorted_box[0]]
        x_clusters = []
        for i in range(1, len(x_sorted_box)):
            last_x_start = x_sorted_box[i-1][1][0]
            last_x_end = x_sorted_box[i-1][1][1]
            this_x_start = x_sorted_box[i][1][0]
            this_x_end = x_sorted_box[i][1][1]

            total_x_range = this_x_end - last_x_start
            gap = this_x_start - last_x_end

            if this_x_start > last_x_end and gap > GAP_THRESH * total_x_range:
                # This is a heuristic to determine if we need to break the x-axis
                num_x_axis_breaks += 1
                x_clusters.append(deepcopy(curr_x_cluster))
                curr_x_cluster = [x_sorted_box[i]]
            else:
                curr_x_cluster.append(x_sorted_box[i])
        
        if len(curr_x_cluster) > 0:
            x_clusters.append(deepcopy(curr_x_cluster))

        x_ranges = [
            (min([v[1][0] for v in cluster]), max([v[1][1] for v in cluster]))
            for cluster in x_clusters
        ]


        y_sorted_box = list(bounding_boxes.items())
        y_sorted_box.sort(key=lambda x: x[1][2])
        curr_y_cluster = [y_sorted_box[0]]
        y_clusters = []
        for i in range(1, len(y_sorted_box)):
            last_y_start = y_sorted_box[i-1][1][2]
            last_y_end = y_sorted_box[i-1][1][3]
            this_y_start = y_sorted_box[i][1][2]
            this_y_end = y_sorted_box[i][1][3]

            total_y_range = this_y_end - last_y_start
            gap = this_y_start - last_y_end

            if this_y_start > last_y_end and gap > GAP_THRESH * total_y_range:
                # This is a heuristic to determine if we need to break the y-axis
                num_y_axis_breaks += 1
                y_clusters.append(deepcopy(curr_y_cluster))
                curr_y_cluster = [y_sorted_box[i]]
            else:
                curr_y_cluster.append(y_sorted_box[i])
        if len(curr_y_cluster) > 0:
            y_clusters.append(deepcopy(curr_y_cluster))

        y_ranges = [
            (min([v[1][2] for v in cluster]), max([v[1][3] for v in cluster]))
            for cluster in y_clusters
        ]

        total_x_axes = num_x_axis_breaks + 1
        total_y_axes = num_y_axis_breaks + 1
        print(total_x_axes, total_y_axes, x_clusters, y_clusters)

        assert(total_x_axes == len(x_ranges))
        assert(total_y_axes == len(y_ranges))

        is_1d = total_x_axes == 1 or total_y_axes == 1

        font = self.kwargs.get('font', {
            'size'   : 65
        })
        matplotlib.rc('font', **font)
        matplotlib.rc("axes.formatter", limits=(-99, 99))

        fig, axes = plt.subplots(
            total_y_axes, total_x_axes,
            figsize=(10 * total_x_axes, 6 * total_y_axes),
            sharex='col', sharey='row',
        )

        print(total_y_axes, total_x_axes)



        num_lines = len(plot_dict)
        colors = self.kwargs.get('colors', ['b', 'g', 'r', 'c', 'm', 'y', 'k', "orange", "c"])
        markers = self.kwargs.get('markers', ['o', 's', 'D', '^', 'v', 'p', 'P', '*', 'X', 'H'])
        while len(colors) < num_lines:
            colors += colors
        while len(markers) < num_lines:
            markers += markers

        
        legends_ncols = self.kwargs.get('legends_ncols', len(plot_dict))
        if legends_ncols > 3:
            legends_ncols = 3

    
        try:
            fig.subplots_adjust(hspace=0.1, wspace=0.1)
            for ax in list(axes.flatten()):
                ax.grid()
                for i, (legend, stat_list) in enumerate(plot_dict.items()):
                    tputs = [stat.mean_tput for stat in stat_list]
                    latencies = [stat.median_latency for stat in stat_list]
                    ax.plot(tputs, latencies, label=legend, color=colors[i], marker=markers[i], mew=6, ms=12, linewidth=6)

        
            self.tput_latency_prepare_plot(fig, axes, x_ranges, y_ranges, is_1d, legends_ncols, total_x_axes, total_y_axes)
        except Exception as e:
            print("Defaulting to normal plot")
            assert not(isinstance(axes, np.ndarray))
            
            if "partitions" in self.kwargs:
                cft_partitions = self.kwargs["partitions"]["cft"]
                bft_partitions = self.kwargs["partitions"]["bft"]
                print(cft_partitions, bft_partitions)
                self.plot_partitions(cft_partitions, bft_partitions, plot_dict, colors, markers, legends_ncols)
            else:
                axes.grid()
                plot_dict_items = list(sorted(plot_dict.items()))

                for i, (legend, stat_list) in enumerate(plot_dict_items):
                    if "Slow" in legend:
                        legend = "Slow Audit"
                    elif "Fast" in legend:
                        legend = "Fast Audit"
                    elif "Crash Commit" in legend:
                        legend = "Commit"
                    tputs = [stat.mean_tput for stat in stat_list]
                    latencies = [stat.median_latency for stat in stat_list]
                    axes.plot(tputs, latencies, label=legend, color=colors[i], marker=markers[i], mew=6, ms=12, linewidth=6)

                    # if "Audit" in legend:
                    #     n_points = len(tputs)
                    #     labels = ["sig=1", "sig=2", "sig=5", "sig=10", "sig=20", "sig=50"]
                    #     for i in range(n_points):
                    #         axes.annotate(labels[i], (tputs[i], latencies[i]), textcoords="offset points", xytext=(0,10), ha='center', fontsize=50)


                plt.xlabel(xlabel, fontsize=70)
                plt.ylabel(ylabel, fontsize=70)

                y_range_total = max([v[3] for v in bounding_boxes.values()]) - min([v[2] for v in bounding_boxes.values()])
                # if y_range_total > 200:
                # plt.yscale("log")
                # plt.ylim((0, 125))
                # plt.xlim((50, 550))
                if logscale:
                    plt.yscale("log")

                plt.legend(loc='upper center', bbox_to_anchor=(0.5, 1.4), ncol=legends_ncols, fontsize=70)
                plt.xticks(fontsize=70)
                plt.yticks(fontsize=70)


        plt.gcf().set_size_inches(
            self.kwargs.get("output_width", 30),
            self.kwargs.get("output_height", 12)
        )

        if output is not None:
            output = os.path.join(self.workdir, output)
            plt.savefig(output, bbox_inches="tight")
        else:
            plt.show()

    def plot_partitions(self, cft_partitions, bft_partitions, plot_dict, colors, markers, legends_ncols):
        # Two figures side by side
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(15, 12))
        fig.subplots_adjust(hspace=0.1, wspace=0.5)

        for i, (legend, stat_list) in enumerate(plot_dict.items()):
            tputs = [stat.mean_tput for stat in stat_list]
            latencies = [stat.median_latency for stat in stat_list]
            if legend in cft_partitions:
                ax1.plot(tputs, latencies, label=legend, color=colors[i], marker=markers[i], mew=6, ms=12, linewidth=6)
            elif legend in bft_partitions:
                ax2.plot(tputs, latencies, label=legend, color=colors[i], marker=markers[i], mew=6, ms=12, linewidth=6)

        ax1.grid()
        ax2.grid()
        ax1.set_xlabel("Throughput (k req/s)", fontsize=70)
        ax1.set_ylabel("Latency (ms)", fontsize=70)
        ax2.set_xlabel("Throughput (k req/s)", fontsize=70)
        ax2.set_ylabel("Latency (ms)", fontsize=70)
        fig.legend(loc='upper center', bbox_to_anchor=(0.5, 1.32), ncol=legends_ncols, fontsize=70, columnspacing=0.5)

        ax1.set_ylim(top=130, bottom=0)
        ax2.set_ylim(top=130, bottom=0)
        ax1.set_xlim(right=600)
        ax2.set_xlim(right=600)
        ax1.set_yticks([25, 50, 75, 100, 125])
        ax2.set_yticks([25, 50, 75, 100, 125])
        ax1.set_xticks([200, 400, 600])
        ax2.set_xticks([200, 400, 600])
        ax1.set_yticklabels([25, 50, 75, 100, 125], fontsize=70)
        ax2.set_yticklabels([25, 50, 75, 100, 125], fontsize=70)
        ax1.set_xticklabels([200, 400, 600], fontsize=70)
        ax2.set_xticklabels([200, 400, 600], fontsize=70)






    def tput_latency_sweep(self):
        '''
        Considers each sub-experiment in a group as a separate data point on a line graph
        and plots in the order of the experiment seq num.
        Each group is a separate line on the graph and len(legends) == len(experiment_groups)
        This expects PirateShip style logging formats.

        Legend guide:
        - <name>: Plot throughput vs latency for crash commit only
        - <name>+byz: Plot byz commit latency separately, new line for <name>-byz
        - <name_1>+<name_2>+byz: Plot byz commit latency separately with legend <name2>
        - <name>+onlybyz: Plot only byz commit latency.
        '''

        # Parse args
        ramp_up = self.kwargs.get('ramp_up', 0)
        ramp_down = self.kwargs.get('ramp_down', 0)
        legends = self.kwargs.get('legends', {})
        force_parse = self.kwargs.get('force_parse', False)

        # Try retreive plot dict from cache
        try:
            if force_parse:
                raise Exception("Force parse")

            with open(os.path.join(self.workdir, "plot_dict.pkl"), "rb") as f:
                plot_dict = pickle.load(f)
        except:
            plot_dict = self.tput_latency_sweep_parse(ramp_up, ramp_down, legends)

        # Save plot dict
        with open(os.path.join(self.workdir, "plot_dict.pkl"), "wb") as f:
            pickle.dump(plot_dict, f)
        # Print a summary of the results
        with open(os.path.join(self.workdir, "summary.txt"), "w") as f:
            for legend, stats in plot_dict.items():
                f.write(f"{legend}\n")
                for stat in stats:
                    f.write(f"=============Num Nodes: {stat.num_nodes}, Num Clients: {stat.num_clients}================\n")
                    f.write(f"Mean Tput: {stat.mean_tput} ktx/s, Mean Latency: {stat.mean_latency} ms\n")
                    f.write(f"Median Latency: {stat.median_latency} ms, 99th Percentile Latency: {stat.p99_latency} ms\n")
                    f.write(f"Max Latency: {stat.max_latency} ms, Min Latency: {stat.min_latency} ms\n")
                    f.write(f"Stdev Tput: {stat.stdev_tput} ktx/s, Stdev Latency: {stat.stdev_latency} ms\n")
                    f.write("==================================\n")

        output = self.kwargs.get('output', None)
        self.tput_latency_sweep_plot(plot_dict, output)



    def stacked_bar_graph_parse(self, ramp_up, ramp_down, legends) -> OrderedDict[str, List[Stats]]:
        return collections.OrderedDict(self.tput_latency_sweep_parse(ramp_up, ramp_down, legends))
    
    def stacked_bar_graph_plot(self, plot_dict: OrderedDict[str, List[Stats]], output: str | None, xlabels: List[str]):
        # Assumption: xlabels are in the same order as the subexperiments in each group
        plot_matrix = np.zeros((len(xlabels), len(plot_dict))) # Rows are xlabels, columns are legends
        stdev_matrix = np.zeros((len(xlabels), len(plot_dict))) # Rows are xlabels, columns are legends
        latency_matrix = np.zeros((len(xlabels), len(plot_dict))) # Rows are xlabels, columns are legends
        max_tput = 0
        # plot_dict_items = list(sorted(plot_dict.items(), key=lambda x: int(x[0].split(" ")[0])))
        plot_dict_items = list(plot_dict.items())
        
        for i, xlabel in enumerate(xlabels):
            for j, (legend, stat_list) in enumerate(plot_dict_items):
                for k, stat in enumerate(stat_list):
                    if i == k:
                        plot_matrix[i, j] = int(stat.mean_tput)
                        stdev_matrix[i, j] = int(stat.stdev_tput)
                        latency_matrix[i, j] = int(float("{:.1f}".format(stat.mean_latency)))
                        if stat.mean_tput > max_tput:
                            max_tput = stat.mean_tput

        ylim = max_tput * 1.1

        bar_width = 0.35
        gap_between_bars = 0.1

        # Stacked bars and then a gap to the right and left
        block_size = 2 * gap_between_bars + len(plot_dict) * bar_width

        bar_start_pos = np.array([i * block_size for i in range(len(xlabels))])
        label_pos = [i * block_size + (len(plot_dict) // 2) * bar_width - 0 * gap_between_bars for i in range(len(xlabels))]

        font = self.kwargs.get('font', {
            'size'   : 90,
            'family': 'serif',
            'serif': ["Linux Libertine O"],
        })
        matplotlib.rc('font', **font)
        matplotlib.rc("axes.formatter", limits=(-99, 99))
        matplotlib.rcParams['ps.useafm'] = True
        matplotlib.rcParams['pdf.use14corefonts'] = True
        matplotlib.rcParams['text.usetex'] = True
        # matplotlib.rcParams["text.latex.preview"] = True
        matplotlib.rcParams['text.latex.preamble'] = r"""
        \usepackage{libertine}
        \usepackage[libertine]{newtxmath}
        """

        fig, ax = plt.subplots(layout="constrained")
        for i, (legend, stats) in enumerate(plot_dict_items):
            rects = ax.bar(
                bar_start_pos + (gap_between_bars + i * bar_width), # Where to start the bar
                plot_matrix[:, i], # Heights of the bars
                width=bar_width, label=legend, zorder=3,

                # Error bars
                yerr=stdev_matrix[:, i], # Error bars
                capsize=5, linewidth=5,   
            )
            # _latencies = list(latency_matrix[:, i])
            # _latencies = [str(int(x)) for x in _latencies]
            # ax.bar_label(rects, labels=_latencies, padding=3, fontsize=90)
            # ax.bar_label(rects, padding=3, fontsize=90)

        ax.set_xticks(label_pos, xlabels)
        plt.ylim(0, ylim+50)
        plt.ylabel("Throughput (k req/s)", fontsize=90)
        if "xtitle" in self.kwargs:
            plt.xlabel(self.kwargs["xtitle"], fontsize=90)
        plt.xticks(fontsize=80)
        plt.yticks([0, 500, 1000, 1500, 2000], fontsize=90)
        # plt.yticks(fontsize=90)

        if len(plot_dict_items) > 1:
            plt.legend(loc="upper center", ncols=2, bbox_to_anchor=(0.5, 1.28), fontsize=60, columnspacing=0.3)
        plt.grid(zorder=0)

        plt.gcf().set_size_inches(
            self.kwargs.get("output_width", 30),
            self.kwargs.get("output_height", 12)
        )

        if output is not None:
            output = os.path.join(self.workdir, output)
            plt.savefig(output, bbox_inches="tight")
        else:
            plt.show()

    def crash_byz_tput_timeseries_plot(self, times, crash_commits, byz_commits, events):
        assert len(times) == len(crash_commits) == len(byz_commits)

        plt.plot(times, crash_commits, label="Commit Throughput", linewidth=10, marker="o", markersize=20)
        plt.plot(times, byz_commits, label="Audit Throughput", linewidth=10, marker="^", markersize=20)
        plt.xlabel("Time (s)", fontsize=70)
        plt.ylabel("Throughput (batch/s)", fontsize=70)

        plt.yscale("symlog")
        # plt.ticklabel_format(scilimits=(-1000000, 1000000))
        

        # Legend at lower right
        # plt.legend(loc="lower right", fontsize=90)
        plt.legend(loc='upper center', bbox_to_anchor=(0.5, 1.25), ncol=2, fontsize=70)

        plt.grid()

        plt.xlim(25, 45)
        plt.xticks(fontsize=90)
        plt.yticks(fontsize=65)


        # How low/high can I go?
        ylim_min = min(min(crash_commits), min(byz_commits))
        ylim_max = max(max(crash_commits), max(byz_commits))

        # Will use this range for all text boxes for events
        text_box_locs = list([-200, -5, 10, -6])
        assert len(text_box_locs) == len(events)


        line_colors = ['r', 'g', 'b', 'c', 'm', 'y', 'k', "orange"]
        text_props = dict(boxstyle='round', facecolor='wheat', alpha=0.5)

        for i, (event_time, event_description) in enumerate(events):
            plt.axvline(x=event_time, color=line_colors.pop(0), linestyle="--", linewidth=8)
            # Large font
            plt.text(
                event_time + 0.2 * i, text_box_locs[i],
                event_description, bbox=text_props,
                horizontalalignment='center',
                verticalalignment='center',
                fontsize=50
            )

        plt.gcf().set_size_inches(
            self.kwargs.get("output_width", 30),
            self.kwargs.get("output_height", 12)
        )
        

        output = self.kwargs.get('output', None)
        if output is not None:
            output = os.path.join(self.workdir, output)
            plt.savefig(output, bbox_inches="tight")
        else:
            plt.show()


    def parse_event(self, event) -> Tuple[float, str]:
        """
        Use the given pattern in the target node to find the event.
        Takes the first capture group (assumed timestamp) and finds the seconds elapsed since start.
        Since there can be clock skew between nodes, it is better to use time relative to start of experiment.
        with the text description.
        """
        description = event.get("description", event.get("name", "Event"))


        experiment_start_pattern = re.compile(r"\[INFO\]\[.*\]\[(.*)\]")

        pattern = event.get("pattern", None)
        if pattern is None:
            patterns = [re.compile(p) for p in event["patterns"]]
        else:
            patterns = [re.compile(pattern)]

        target_node = event["target"]
        log_path = os.path.join(self.experiments[0].get_local_workdir(), "logs", "0", f"{target_node}.log")

        target_occurrence_num = event.get("occurrence_num", 1)
        occurrence_num = 0
        start_time = None
        with open(log_path, "r") as f:
            for line in f.readlines():
                if start_time is None:
                    # Is this the line with start time?
                    captures = experiment_start_pattern.findall(line)
                    if len(captures) > 0:
                        start_time = isoparse(captures[0])

                for pattern in patterns:
                    captures = pattern.findall(line)
                    if len(captures) > 0:
                        occurrence_num += 1
                        if occurrence_num == target_occurrence_num:
                            assert start_time is not None
                            return ((isoparse(captures[0]) - start_time).total_seconds(), description)


    def crash_byz_tput_timeseries(self):
        # Parse args
        ramp_up = self.kwargs.get('ramp_up', 0)
        ramp_down = self.kwargs.get('ramp_down', 0)
        force_parse = self.kwargs.get('force_parse', False)
        target_node = self.kwargs.get('target_node', "node1")

        

        # Try to fetch points from cache
        try:
            if force_parse:
                raise Exception("Force parse")

            with open(os.path.join(self.workdir, "points.pkl"), "rb") as f:
                sampled_points, events = pickle.load(f)
        except:
            # Have to parse the logs
            assert len(self.experiment_groups) == 1, "Only one group is allowed for this plotter"
            assert len(self.experiment_groups) == 1, "Only one group is allowed for this plotter"
            events = self.kwargs.get('events', [])
            events = [
                self.parse_event(event)
                for event in events
            ]

            expr = list(self.experiment_groups.values())[0]

            tputs = []
            tputs_unbatched = []
            log_dir = f"{expr[0].get_local_workdir()}/logs/0"
            points = self.parse_node_logs(
                log_dir, [f"{target_node}.log"],
                expr[0].duration,
                ramp_up, ramp_down, tputs, tputs_unbatched
            )


            # Change absolute time to time relative to start
            start_time = points[0][0]

            sample_rate = self.kwargs.get('sample_rate', 10)

            for i in range(len(points)):
                points[i] = list(points[i])
                points[i][0] -= start_time
                points[i][0] = points[i][0].total_seconds()

            sampled_points = []
            for i in range(sample_rate, len(points), sample_rate):
                # Instantaneous throughput calculation
                ci_tput = (points[i][3] - points[i-sample_rate][3]) / (points[i][0] - points[i-sample_rate][0])
                bci_tput = (points[i][4] - points[i-sample_rate][4]) / (points[i][0] - points[i-sample_rate][0])
                time_instant = points[i][0] + ramp_up
                sampled_points.append((time_instant, ci_tput, bci_tput))

            

        # Save the points
        with open(os.path.join(self.workdir, "points.pkl"), "wb") as f:
            pickle.dump((sampled_points, events), f)

        times = [p[0] for p in sampled_points]
        crash_commits = [p[1] for p in sampled_points]
        byz_commits = [p[2] for p in sampled_points]

        print(times)
        print(crash_commits)
        print(byz_commits)
        print(events)

        self.crash_byz_tput_timeseries_plot(times, crash_commits, byz_commits, events)

    def stacked_bar_graph(self):
        # Parse args
        ramp_up = self.kwargs.get('ramp_up', 0)
        ramp_down = self.kwargs.get('ramp_down', 0)
        legends = self.kwargs.get('legends', {})
        force_parse = self.kwargs.get('force_parse', False)
        xlabels = self.kwargs.get('xlabels', [])

        # Number of xlabels must match number of subexperiments for each group.
        for group_name, experiments in self.experiment_groups.items():
            if len(xlabels) != len(experiments):
                print("\x1b[31;1mNumber of xlabels must match number of subexperiments for each group.\x1b[0m")
                raise Exception("Number of xlabels must match number of subexperiments for each group.")

        # Try retreive plot dict from cache
        try:
            if force_parse:
                raise Exception("Force parse")

            with open(os.path.join(self.workdir, "plot_dict.pkl"), "rb") as f:
                plot_dict = pickle.load(f)
        except:
            plot_dict = self.stacked_bar_graph_parse(ramp_up, ramp_down, legends)

        # Save plot dict
        with open(os.path.join(self.workdir, "plot_dict.pkl"), "wb") as f:
            pickle.dump(plot_dict, f)

        output = self.kwargs.get('output', None)
        self.stacked_bar_graph_plot(plot_dict, output, xlabels)

    def update_experiments(self, experiments):
        self.experiments = experiments[:]
        self.experiment_groups = defaultdict(list)
        for experiment in self.experiments:
            self.experiment_groups[experiment.group_name].append(experiment)

    def __init__(self, name, workdir, fn_name, experiments, kwargs):
        self.name = name

        self.workdir = os.path.join(workdir, "results", self.name)
        os.makedirs(self.workdir, exist_ok=True)

        self.plotter_func = getattr(self, fn_name, self.default_output)
        self.update_experiments(experiments)
        
        self.kwargs = deepcopy(kwargs)

    def output(self):
        self.plotter_func()

    # RESOURCES

    def resource_timeseries(self):
        """Plot combined resource usage for leader, followers, and clients in single plots."""
        ramp_up = self.kwargs.get('ramp_up', 25)
        ramp_down = self.kwargs.get('ramp_down', 15)
        output_dir = self.workdir

        os.makedirs(output_dir, exist_ok=True)
        
        for group_name, experiment_list in self.experiment_groups.items():
            for experiment in experiment_list:
                variant_name = str(experiment.seq_num)
                variant_label = f"{group_name}-{variant_name}"
                
                print(f"Processing combined resources for {variant_label}")
                
                log_dirs = []
                for repeat_num in range(experiment.repeats):
                    log_dir = os.path.join(experiment.get_local_workdir(), "logs", str(repeat_num))
                    if os.path.exists(log_dir) and os.listdir(log_dir):
                        log_dirs.append(log_dir)
                
                if not log_dirs:
                    continue

                leader_resources = {rt : [] for rt in RESOURCE_TYPES}
                follower_resources = {rt : [] for rt in RESOURCE_TYPES}
                client_resources = { rt : [] for rt in RESOURCE_TYPES}
                
                for log_dir in log_dirs:
                    leader_res, follower_res, client_res = self.parse_resource_data(log_dir, experiment.duration, ramp_up, ramp_down)
                    
                    if not leader_res or not follower_res or not client_res:
                        print(f"Missing resource data for {variant_label} in {log_dir}")
                        continue
                    for resource_type in RESOURCE_TYPES:
                        for res in leader_res:
                            if resource_type in res:
                                leader_resources[resource_type].append(res[resource_type])
                    
                    for resource_type in RESOURCE_TYPES:
                        run_follower_data = []
                        for res in follower_res:
                            if resource_type in res:
                                run_follower_data.append(res[resource_type])
                        
                        if run_follower_data:
                            # Average across all followers for this single run
                            min_len = min(len(ts) for ts in run_follower_data)
                            averaged_data = []
                            for i in range(min_len):
                                timestamp = run_follower_data[0][i][0]
                                avg_val = np.mean([ts[i][1] for ts in run_follower_data])
                                averaged_data.append((timestamp, avg_val))
                            follower_resources[resource_type].append(averaged_data)
                    
                    for resource_type in RESOURCE_TYPES:
                        run_client_data = []
                        for res in client_res:
                            if resource_type in res:
                                run_client_data.append(res[resource_type])
                        
                        if run_client_data:
                            # Average across all clients for this single run
                            min_len = min(len(ts) for ts in run_client_data)
                            averaged_data = []
                            for i in range(min_len):
                                timestamp = run_client_data[0][i][0]
                                avg_val = np.mean([ts[i][1] for ts in run_client_data])
                                averaged_data.append((timestamp, avg_val))
                            client_resources[resource_type].append(averaged_data)
                
                self.plot_combined_resource_panel(leader_resources, follower_resources, client_resources, variant_label, output_dir)

    def parse_resource_data(self, log_dir: str, duration: int, ramp_up: int, ramp_down: int):
        leader_resources = []
        node_resources = []
        client_resources = []
        
        for f in os.listdir(log_dir):
            if f.startswith('node') and f.endswith('.stats.csv'):
                stats = parse_stats_file(os.path.join(log_dir, f), duration, ramp_up, ramp_down)
                if stats:
                    if f.startswith('node1'):
                        leader_resources.append(stats)
                    else:
                        node_resources.append(stats)
        
        for f in os.listdir(log_dir):
            if f.startswith('client') and f.endswith('.stats.csv'):
                stats = parse_stats_file(os.path.join(log_dir, f), duration, ramp_up, ramp_down)
                if stats:
                    client_resources.append(stats)
        
        return leader_resources, node_resources, client_resources

    def plot_combined_resource_panel(self, leader_resources, follower_resources, client_resources, 
                                   variant_label, output_dir):
        """Plot leader, followers, and clients resources in a single panel."""
        plt.switch_backend('Agg')
        plt.rcParams.update({'font.size': 12})

        fig, axes = plt.subplots(3, 2, figsize=(20, 15))
        axes = axes.flatten()

        resource_info = [
            ('cpu', 'CPU Usage (\%)', 'CPU Usage'),
            ('memory', 'Memory (MB)', 'Memory Usage'),
            ('net_recv', 'Network Recv (MB/s)', 'Network Receive'),
            ('net_send', 'Network Send (MB/s)', 'Network Send'),
            ('disk_read', 'Disk Read (MB/s)', 'Disk Read'),
            ('disk_write', 'Disk Write (MB/s)', 'Disk Write')
        ]

        colors = ['#1f77b4', '#ff7f0e', '#2ca02c']  # Blue, Orange, Green
        labels = ['Leader (node1)', 'Followers (avg)', 'Clients (avg)']
        
        for i, (resource_type, ylabel, title) in enumerate(resource_info):
            ax = axes[i]
            
            resource_sets = [leader_resources, follower_resources, client_resources]
            
            for j, (resources, color, label) in enumerate(zip(resource_sets, colors, labels)):
                if not resources[resource_type]:
                    continue
                    
                if len(resources[resource_type]) > 1:
                    # Average across multiple runs
                    min_len = min(len(ts) for ts in resources[resource_type])
                    times = list(range(min_len))
                    means = []
                    stds = []
                    for i_time in range(min_len):
                        values = [ts[i_time][1] for ts in resources[resource_type]]
                        means.append(np.mean(values))
                        stds.append(np.std(values))
                    
                    ax.plot(times, means, linewidth=2, color=color, label=label)
                    ax.fill_between(times,
                                  [max(0, m - s) for m, s in zip(means, stds)],
                                  [m + s for m, s in zip(means, stds)],
                                  alpha=0.2, color=color)
                else:
                    ts = resources[resource_type][0]
                    times = list(range(len(ts)))
                    values = [point[1] for point in ts]
                    ax.plot(times, values, linewidth=2, color=color, label=label)
                        
            ax.set_xlabel('Time (seconds)')
            ax.set_ylabel(ylabel)
            ax.set_title(f'{title} - {variant_label}')
            ax.legend()
            ax.grid(True, alpha=0.3)

        plt.tight_layout()
        output_file = os.path.join(output_dir, f'{variant_label}.pdf')
        plt.savefig(output_file, dpi=150, bbox_inches='tight')
        plt.close()
        print(f"{variant_label} combined resources plot saved to {output_file}")

    # SCITT

    def tput_latency_sweep_locust(self):
        '''
        ***** Mimic tput_latency_sweep but using locust results *****

        Considers each sub-experiment in a group as a separate data point on a line graph
        and plots in the order of the experiment seq num.
        Each group is a separate line on the graph and len(legends) == len(experiment_groups)
        This expects Locust json output format.
        '''

        # Parse args
        ramp_up = self.kwargs.get('ramp_up', 0)
        ramp_down = self.kwargs.get('ramp_down', 0)
        legends = self.kwargs.get('legends', {})
        force_parse = self.kwargs.get('force_parse', False)

        # Try retreive plot dict from cache
        try:
            if force_parse:
                raise Exception("Force parse")

            with open(os.path.join(self.workdir, "plot_dict.pkl"), "rb") as f:
                plot_dict = pickle.load(f)
        except:
            plot_dict = self.tput_latency_sweep_parse_locust(ramp_up, ramp_down, legends)

        # Save plot dict
        with open(os.path.join(self.workdir, "plot_dict.pkl"), "wb") as f:
            pickle.dump(plot_dict, f)
        # Print a summary of the results
        with open(os.path.join(self.workdir, "summary.txt"), "w") as f:
            for legend, stats in plot_dict.items():
                f.write(f"{legend}\n")
                for stat in stats:
                    f.write(f"=============Num Nodes: {stat.num_nodes}, Num Clients: {stat.num_clients}================\n")
                    f.write(f"Mean Tput: {stat.mean_tput} claims/s, Mean Latency: {stat.mean_latency} ms\n")
                    f.write(f"Median Latency: {stat.median_latency} ms, 99th Percentile Latency: {stat.p99_latency} ms\n")
                    f.write(f"Max Latency: {stat.max_latency} ms, Min Latency: {stat.min_latency} ms\n")
                    f.write(f"Stdev Tput: {stat.stdev_tput} claims/s, Stdev Latency: {stat.stdev_latency} ms\n")
                    f.write("==================================\n")

        output = self.kwargs.get('output', None)
        self.tput_latency_sweep_plot(plot_dict, output, xlabel="Throughput (claims/s)", ylabel="Latency (ms)", logscale=False)

    def tput_latency_sweep_parse_locust(self, ramp_up, ramp_down, legends) -> Dict[str, List[Stats]]:
        plot_dict = {}

        # Which indices do I skip?
        skip_indices = self.kwargs.get('skip_indices', [])

        # Find parsing log files for each group
        for group_name, experiments in self.experiment_groups.items():
            print("========", group_name, "========")
            experiments.sort(key=lambda x: x.seq_num)
            crash_legend = None
            byz_legend = None
            legend = legends.get(group_name, None)
            if legend is None:
                print("\x1b[31;1mNo legend found for", group_name, ". Skipping...\x1b[0m")
                continue

            final_stats = []

            for idx, experiment in enumerate(experiments):
                if idx in skip_indices:
                    print("\x1b[31;1mSkipping experiment", experiment.name, "for crash commit\x1b[0m")
                    continue
                stats = self.process_locust_experiment(experiment, ramp_up, ramp_down)
                if stats is not None:
                    final_stats.append(stats)
                else:
                    print("\x1b[31;1mSkipping experiment", experiment.name, "for crash commit\x1b[0m")

                plot_dict[legend] = final_stats

        pprint(plot_dict)
        return plot_dict


    def parse_locust_client_logs(self, log_dir, logs, duration, ramp_up, ramp_down):
        latencies = {}
        tput = {}
        for log_name in logs:
            fname = os.path.join(log_dir, log_name)
            try:
                with open(fname, "r") as f:
                    result = json.load(f)[0]
                    num_reqs_per_sec = result.get("num_reqs_per_sec", {})
                    if len(num_reqs_per_sec) == 0:
                        print(f"\x1b[31;1mNo requests per second data found in {fname}. Skipping...\x1b[0m")
                        continue
                    for key, value in num_reqs_per_sec.items():
                        key = int(key)
                        if key not in tput:
                            tput[key] = 0
                        tput[key] += int(value)
                    reponse_times = result.get("response_times", {})
                    if len(reponse_times) == 0:
                        print(f"\x1b[31;1mNo response times data found in {fname}. Skipping...\x1b[0m")
                        continue
                    for key, value in reponse_times.items():
                        key = float(key)
                        if key not in latencies:
                            latencies[key] = 0
                        latencies[key] += int(value)
                    if (failures := result.get("num_fail_per_sec" ,{})) != {}:
                        total = sum(failures.values())
                        if total > 10:
                            print(f"\x1b[31;1mFound failures in {fname}({total})\x1b[0m")
                        # otherwise we just ignore for now
                        
            except Exception as e:
                print(f"\x1b[31;1mError reading {fname}. Skipping...\x1b[0m")
                print(f"\x1b[31;1mError details: {e}\x1b[0m")
                pass
        start = min(tput.keys())
        end = max(tput.keys())
        start_time = start + ramp_up
        end_time = end + duration - ramp_down

        for key in list(tput.keys()):
            if key < start_time or key > end_time:
                del tput[key]
        tput = [tput[ts] for ts in sorted(tput.keys())]

        latencies = [latency for latency in latencies for _ in range(latencies[latency])]

        return tput, latencies

    def process_locust_experiment(self, experiment, ramp_up, ramp_down, tput_scale=1000.0, latency_scale=1000.0) -> Stats | None:
        tputs = []
        latencies = []
        duration = experiment.duration
        for repeat_num in range(experiment.repeats):
            log_dir = os.path.join(experiment.get_local_workdir(), "logs", str(repeat_num))
            # Find the first node log file and all client log files in log_dir
            # node_log_files = list(sorted([f for f in os.listdir(log_dir) if f.startswith("node") and f.endswith(".log")]))
            client_log_files = [f for f in os.listdir(log_dir) if f.startswith("client") and f.endswith(".log")]

            # self.parse_node_logs(log_dir, node_log_files, duration, ramp_up, ramp_down, tputs, tputs_unbatched, byz=byz)
            t, l = self.parse_locust_client_logs(log_dir, client_log_files, duration, ramp_up, ramp_down)
            tputs.extend(t)
            latencies.extend(l)

        print(len(tputs), len(latencies))
        if len(latencies) == 0:
            return None
        latency_prob_dist = np.array(latencies)
        latency_prob_dist.sort()
        try:
            stdev_tput = np.std(tputs)
        except:
            stdev_tput = 0
        
        try:
            stdev_latency = np.std(latencies)
        except:
            stdev_latency = 0

        mean_latency = np.mean(latencies)

        try:
            median_latency = np.median(latencies)
            p25_latency=np.percentile(latencies, 25),
            p75_latency=np.percentile(latencies, 75),
            p99_latency=np.percentile(latencies, 99),
        except:
            median_latency = mean_latency
            p25_latency = mean_latency
            p75_latency = mean_latency
            p99_latency = mean_latency

        ret = Stats(
            num_nodes=experiment.num_nodes,
            num_clients=experiment.num_clients,
            mean_tput=np.mean(tputs),
            stdev_tput=stdev_tput,
            mean_tput_unbatched=0,
            stdev_tput_unbatched=0,
            latency_prob_dist=latency_prob_dist,
            mean_latency=mean_latency,
            median_latency=median_latency,
            p25_latency=p25_latency,
            p75_latency=p75_latency,
            p99_latency=p99_latency,
            max_latency=np.max(latencies),
            min_latency=np.min(latencies),
            stdev_latency=stdev_latency
        )

        return ret