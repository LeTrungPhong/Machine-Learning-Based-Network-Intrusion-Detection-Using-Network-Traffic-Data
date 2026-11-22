# -*- coding: utf-8 -*-
"""Kiểm thử bắt lưu lượng thật (không cần quyền Admin/mạng): card mạng, gom cảnh báo, whitelist, pipeline pcap -> CSV."""
import sys
import textwrap
import time

import numpy as np
import pandas as pd
import pytest

from adapters.live_capture import CaptureSession, parse_interfaces
from adapters.live_source import FlowSimulator, LiveFolderSource, add_synthetic_ips
from core.alerting import AlertAggregator, load_whitelist, parse_list, save_whitelist, whitelist_mask

DUMPCAP_D = r"""1. \Device\NPF_{EA14} (Local Area Connection* 10)
6. \Device\NPF_{819D} (VMware Network Adapter VMnet1)
7. \Device\NPF_{EE7E} (Wi-Fi)
10. \Device\NPF_Loopback (Adapter for loopback traffic capture)
"""


def test_parse_interfaces():
    ifs = parse_interfaces(DUMPCAP_D)
    assert [i.index for i in ifs] == ['1', '6', '7', '10']
    assert ifs[2].name == 'Wi-Fi' and ifs[2].device.endswith('EE7E}')
    assert 'Host-only' in ifs[1].label


def _info(src, n, port=22):
    return pd.DataFrame({'Src IP': [src] * n, 'Dst IP': ['192.168.56.1'] * n, 'Dst Port': [float(port)] * n})


def test_aggregator_threshold_window_cooldown():
    agg = AlertAggregator(window_s=60, min_flows=5)
    lab, conf = np.array(['PortScan'] * 4), np.full(4, 0.95)
    assert len(agg.add(_info('10.0.0.5', 4), lab, conf, np.ones(4, bool), now=0)) == 0        # 4 < 5
    a = agg.add(_info('10.0.0.5', 1), lab[:1], conf[:1], np.ones(1, bool), now=10)
    assert len(a) == 1 and a.iloc[0]['IP nguồn'] == '10.0.0.5' and a.iloc[0]['Số luồng'] == 5
    assert a.iloc[0]['Cổng đích'] == '22' and a.iloc[0]['Loại tấn công'] == 'PortScan'
    # cooldown: thêm luồng ngay sau đó không cảnh báo lặp
    assert len(agg.add(_info('10.0.0.5', 10), np.array(['PortScan'] * 10), np.full(10, .9), np.ones(10, bool), now=20)) == 0
    # luồng không nghi ngờ không được tính
    assert len(agg.add(_info('10.0.0.9', 9), np.array(['Benign'] * 9), np.full(9, .9), np.zeros(9, bool), now=30)) == 0
    # luồng cũ hết hạn khỏi cửa sổ
    agg2 = AlertAggregator(window_s=60, min_flows=5)
    agg2.add(_info('1.1.1.1', 3), lab[:3], conf[:3], np.ones(3, bool), now=0)
    assert len(agg2.add(_info('1.1.1.1', 3), lab[:3], conf[:3], np.ones(3, bool), now=100)) == 0


def test_whitelist(tmp_path):
    info = pd.DataFrame({'Src IP': ['192.168.1.1', '10.0.0.2', '10.0.0.3'], 'Dst IP': ['x', '8.8.8.8', 'y'],
                         'Dst Port': [443.0, 80.0, 53.0]})
    m = whitelist_mask(info, {'ips': ['192.168.1.1', '8.8.8.8'], 'ports': [53]})
    assert m.tolist() == [True, True, True]
    assert whitelist_mask(info, {'ips': [], 'ports': []}).tolist() == [False] * 3
    p = tmp_path / 'wl.json'
    save_whitelist(parse_list('192.168.1.1; 10.0.0.1,'), parse_list('53, 123, abc', int), path=p)
    assert load_whitelist(p) == {'ips': ['10.0.0.1', '192.168.1.1'], 'ports': [53, 123]}


def test_synthetic_ips_for_simulation():
    df = pd.DataFrame({'Flow Duration': range(6), 'Label': ['BENIGN', 'PortScan', 'PortScan', 'DDoS', 'BENIGN', 'Bot']})
    out = add_synthetic_ips(df)
    assert {'Src IP', 'Dst IP'} <= set(out.columns)
    assert out.loc[1, 'Src IP'] == out.loc[2, 'Src IP'] != out.loc[3, 'Src IP']
    assert add_synthetic_ips(out) is out                       # đã có IP -> giữ nguyên


FAKE_DUMPCAP = textwrap.dedent('''
    import sys, time, pathlib
    out = pathlib.Path(sys.argv[sys.argv.index('-w') + 1])
    for i in range(1, 3):
        (out.parent / f'{out.stem}_0000{i}_20260101.pcap').write_bytes(b'x' * 100)
    time.sleep(60)
''')
FAKE_CSV_ROWS = ['Src IP,Dst IP,Dst Port,Flow Duration,Label',
                 '10.0.0.5,10.0.0.1,22,100,NeedManualLabel',
                 '10.0.0.5,10.0.0.1,23,50,NeedManualLabel']
FAKE_CFM = '\n'.join([
    'import sys, pathlib',
    'pcap, out = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])',
    f'rows = {FAKE_CSV_ROWS!r}',
    "(out / (pcap.name + '_Flow.csv')).write_text(chr(10).join(rows) + chr(10))",
]) + '\n'


@pytest.mark.parametrize('benign', [False, True])
def test_capture_pipeline(tmp_path, benign):
    (tmp_path / 'dumpcap.py').write_text(FAKE_DUMPCAP)
    (tmp_path / 'cfm.py').write_text(FAKE_CFM)
    out = tmp_path / 'out'
    s = CaptureSession('7', out_dir=out, benign=benign, rotate_s=1, capture_dir=tmp_path / 'cap',
                       dumpcap=[sys.executable, str(tmp_path / 'dumpcap.py')],
                       flow_cmd=lambda p, o: [sys.executable, str(tmp_path / 'cfm.py'), str(p), str(o)])
    src = LiveFolderSource(out, pattern='live_*.csv')
    src.reset(skip_existing=True)
    s.start()
    deadline = time.time() + 20
    while s.files_done < 1 and time.time() < deadline:      # file 1 xong (file 2 coi như đang ghi)
        time.sleep(0.3)
    s.stop()                                                 # xử lý nốt file 2
    assert s.files_done == 2 and s.flows_written == 4, s.log
    df = src.get_flows()
    assert len(df) == 4
    assert set(df['Label']) == ({'BENIGN'} if benign else {'NeedManualLabel'})
    assert not list((s.capture_dir).glob('*.pcap'))         # pcap tạm đã xóa


def test_capture_dumpcap_exits_immediately(tmp_path):
    from adapters.base import SourceUnavailable
    (tmp_path / 'bad.py').write_text('import sys; sys.stderr.write("permission denied"); sys.exit(2)')
    s = CaptureSession('7', out_dir=tmp_path / 'o', capture_dir=tmp_path / 'c',
                       dumpcap=[sys.executable, str(tmp_path / 'bad.py')], flow_cmd=lambda p, o: ['x'])
    with pytest.raises(SourceUnavailable) as e:
        s.start()
    assert 'permission denied' in str(e.value) and 'Administrator' in e.value.help_md
