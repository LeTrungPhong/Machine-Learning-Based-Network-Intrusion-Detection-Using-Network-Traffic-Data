# -*- coding: utf-8 -*-
"""Kiểm thử các adapter: PCAP báo lỗi thân thiện khi thiếu backend, giám sát chỉ đọc dòng mới."""
import pandas as pd
import pytest

import config
from adapters import pcap_source
from adapters.base import SourceUnavailable
from adapters.live_source import FlowSimulator, LiveFolderSource


def test_pcap_without_backend_raises_friendly(tmp_path, monkeypatch):
    monkeypatch.setattr(pcap_source, 'python_backend_cmd', lambda: None)
    monkeypatch.setattr(pcap_source, 'java_backend_cmd', lambda: None)
    f = tmp_path / 'x.pcap'
    f.write_bytes(b'\x00' * 24)
    with pytest.raises(SourceUnavailable) as e:
        pcap_source.PcapSource(f, work_dir=tmp_path).get_flows()
    assert 'pip install cicflowmeter' in e.value.help_md


def test_live_reads_only_new_rows(tmp_path):
    src = LiveFolderSource(tmp_path)
    f = tmp_path / 'flows.csv'
    f.write_text('A,B\n1,2\n3,4\n', encoding='utf-8')
    assert len(src.get_flows()) == 2
    assert len(src.get_flows()) == 0                      # không có dòng mới
    with open(f, 'a', encoding='utf-8') as fh:
        fh.write('5,6\n7,')                               # dòng cuối đang ghi dở
    df = src.get_flows()
    assert df[['A', 'B']].values.tolist() == [[5, 6]]
    with open(f, 'a', encoding='utf-8') as fh:
        fh.write('8\n')
    assert src.get_flows()[['A', 'B']].values.tolist() == [[7, 8]]


def test_live_skip_existing(tmp_path):
    f = tmp_path / 'flows.csv'
    f.write_text('A,B\n1,2\n', encoding='utf-8')
    src = LiveFolderSource(tmp_path)
    src.reset(skip_existing=True)
    assert len(src.get_flows()) == 0
    with open(f, 'a', encoding='utf-8') as fh:
        fh.write('3,4\n')
    assert len(src.get_flows()) == 1


def test_live_missing_dir(tmp_path):
    with pytest.raises(SourceUnavailable):
        LiveFolderSource(tmp_path / 'khong_co').get_flows()


def test_simulator_roundtrip(tmp_path):
    sample = pd.DataFrame({'Flow Duration': range(120), 'Label': ['BENIGN'] * 120})
    sim = FlowSimulator(sample, watch_dir=tmp_path, chunk_rows=50)
    sim.start()
    src = LiveFolderSource(tmp_path)
    total = 0
    while sim.step():
        total += len(src.get_flows())
    assert total == 120
