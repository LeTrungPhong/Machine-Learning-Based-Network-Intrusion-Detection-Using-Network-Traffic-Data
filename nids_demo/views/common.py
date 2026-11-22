# -*- coding: utf-8 -*-
"""Thành phần giao diện dùng chung giữa các trang."""
from dataclasses import dataclass

import numpy as np
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

import config
from core.predictor import evaluate

GREEN, RED, BLUE, ORANGE = '#16A34A', '#DC2626', '#2563EB', '#F28C28'
MODEL_COLORS = {'Random Forest': BLUE, 'CNN-BiLSTM': ORANGE}
TASK_LABEL = {'multi': 'Đa lớp', 'binary': 'Nhị phân'}


@dataclass
class Ctx:
    art: object
    predictor: object
    model_choice: str      # tên mô hình hoặc config.COMPARE_MODE
    task: str              # 'multi' | 'binary'
    threshold: float
    dataset: str = config.DEFAULT_DATASET

    @property
    def cfg(self):
        return config.DATASETS[self.dataset]

    @property
    def sample_csv(self):
        return self.cfg['sample_csv']

    @property
    def models(self):
        """Danh sách mô hình cần chạy theo lựa chọn ở sidebar."""
        names = config.MODEL_NAMES if self.model_choice == config.COMPARE_MODE else [self.model_choice]
        return [m for m in names if self.art.has(m, self.task)]


def ctx() -> Ctx:
    return st.session_state['ctx']


@st.cache_data(show_spinner='Đang đọc dữ liệu mẫu...')
def _read_sample(dataset, path, mtime):
    return pd.read_csv(path, low_memory=False)


def load_sample(dataset=None):
    """Đọc dữ liệu mẫu của bộ dữ liệu đang chọn (None nếu chưa có)."""
    dataset = dataset or ctx().dataset
    path = config.DATASETS[dataset]['sample_csv']
    if not path.exists():
        return None
    return _read_sample(dataset, str(path), path.stat().st_mtime)


def sample_token():
    return f'sample:{ctx().dataset}'


def sample_missing_help():
    c = ctx()
    rel = c.sample_csv.relative_to(config.BASE_DIR) if c.sample_csv.is_relative_to(config.BASE_DIR) else c.sample_csv
    st.info(f'Chưa có dữ liệu mẫu `{rel}`. '
            'Chạy `tools/kaggle_export_sample.py` trong một cell trên Kaggle (cùng input CIC-IDS2017), '
            'tải `sample_test.csv` về và đặt vào thư mục `data/`. Trong lúc chờ, bạn có thể tải CSV lên ở trang '
            '"Phân tích file CSV".')


def run_cached(df, token, model_name, task):
    """Dự đoán và lưu kết quả vào session_state theo (token dữ liệu, mô hình, bài toán)."""
    cache = st.session_state.setdefault('pred_cache', {})
    key = (ctx().dataset, token, model_name, task)
    if key not in cache:
        cache[key] = ctx().predictor.predict(df, model_name, task)
    return cache[key]


def note():
    st.caption('⚠️ ' + config.UI_NOTE)


# ----------------------------------------------------------------------------- báo cáo khớp cột
def show_align_report(rep):
    with st.expander(f'Báo cáo khớp cột – khớp {len(rep.matched)}/{rep.n_expected} cột ({rep.match_ratio:.0%})',
                     expanded=rep.match_ratio < 1):
        c = st.columns(4)
        c[0].metric('Cột mô hình cần', rep.n_expected)
        c[1].metric('Cột khớp', len(rep.matched))
        c[2].metric('Cột thiếu', len(rep.missing))
        c[3].metric('Cột thừa (không dùng)', len(rep.extra))
        if rep.missing:
            st.warning('Cột thiếu được điền **median của tập train** (giống notebook) – kết quả có thể kém tin cậy: '
                       + ', '.join(rep.missing))
        if rep.renamed:
            st.write('Cột được đổi tên về tên lúc huấn luyện:')
            st.dataframe(pd.DataFrame({'Tên trong file': list(rep.renamed), 'Tên huấn luyện': list(rep.renamed.values())}),
                         hide_index=True, width='stretch', height=min(35 * (len(rep.renamed) + 1), 250))
        if rep.extra:
            st.caption('Cột thừa: ' + ', '.join(map(str, rep.extra[:60])) + (' …' if len(rep.extra) > 60 else ''))
        if rep.info_cols:
            st.caption('Cột thông tin giữ lại để hiển thị (không đưa vào mô hình): ' + ', '.join(rep.info_cols))


# ----------------------------------------------------------------------------- kết quả
def _style_rows(df):
    def color(row):
        c = '#FEE2E2' if row['Normal/Attack'] == 'Attack' else '#DCFCE7'
        return [f'background-color: {c}'] * len(row)
    return df.style.apply(color, axis=1).format({'Độ tin cậy': '{:.3f}'})


def result_table(pred, info, y_true, threshold):
    out = pd.concat([info.reset_index(drop=True), pred.frame(threshold)], axis=1)
    if y_true is not None:
        out.insert(len(info.columns), 'Nhãn thật', np.asarray(y_true))
    return out


def plot_confusion(cm, labels, title):
    cmn = cm / np.clip(cm.sum(axis=1, keepdims=True), 1, None)
    fig = go.Figure(go.Heatmap(z=cmn, x=labels, y=labels, colorscale='Blues', zmin=0, zmax=1,
                               text=cm, texttemplate='%{text}', hovertemplate='Thật %{y} → Dự đoán %{x}: %{text}<extra></extra>'))
    fig.update_layout(title=title, xaxis_title='Dự đoán', yaxis_title='Thật', yaxis_autorange='reversed',
                      height=420 + 18 * len(labels), margin=dict(l=10, r=10, t=50, b=10))
    return fig


def show_results(pred, info, y_true, threshold, key):
    """KPI, phân bố nhãn, bảng tô màu, lọc, tải CSV và (nếu có nhãn thật) đánh giá."""
    n = len(pred.labels)
    n_att = int(pred.is_attack.sum())
    n_alert = int((pred.is_attack & (pred.confidence >= threshold)).sum())
    c = st.columns(5)
    c[0].metric('Tổng số luồng', f'{n:,}')
    c[1].metric('Dự đoán Attack', f'{n_att:,}')
    c[2].metric('% Attack', f'{n_att / max(n, 1):.1%}')
    c[3].metric(f'Cảnh báo (tin cậy ≥ {threshold:.2f})', f'{n_alert:,}')
    c[4].metric('Thời gian suy luận', f'{pred.seconds:.2f} s', f'{pred.ms_per_1000:.1f} ms / 1.000 luồng', delta_color='off')

    table = result_table(pred, info, y_true, threshold)
    left, right = st.columns([1, 1])
    with left:
        vc = table['Dự đoán'].value_counts().rename_axis('Nhãn').reset_index(name='Số luồng')
        normal = pred.normal
        fig = px.bar(vc, x='Số luồng', y='Nhãn', orientation='h', text='Số luồng', log_x=len(vc) > 2,
                     color=np.where(vc['Nhãn'] == normal, 'Normal', 'Attack'),
                     color_discrete_map={'Normal': GREEN, 'Attack': RED})
        fig.update_layout(title='Phân bố nhãn dự đoán', showlegend=False, height=360,
                          yaxis={'categoryorder': 'total ascending'}, margin=dict(l=10, r=10, t=50, b=10))
        st.plotly_chart(fig, width='stretch', key=f'{key}_dist')
    with right:
        att = table[table['Normal/Attack'] == 'Attack']
        if len(att):
            fig = px.histogram(att, x='Độ tin cậy', nbins=20, color_discrete_sequence=[RED])
            fig.add_vline(x=threshold, line_dash='dash', annotation_text='ngưỡng')
            fig.update_layout(title='Độ tin cậy của các dự đoán Attack', height=360, margin=dict(l=10, r=10, t=50, b=10))
            st.plotly_chart(fig, width='stretch', key=f'{key}_conf')
        else:
            st.success('Không phát hiện luồng tấn công nào.')

    labels = sorted(table['Dự đoán'].unique())
    f1, f2 = st.columns([3, 1])
    sel = f1.multiselect('Lọc theo nhãn dự đoán', labels, default=labels, key=f'{key}_filter')
    only_alert = f2.checkbox('Chỉ hiện cảnh báo', key=f'{key}_alert')
    view = table[table['Dự đoán'].isin(sel)]
    if only_alert:
        view = view[view['Cảnh báo']]
    st.caption(f'{len(view):,} dòng' + (f' – chỉ tô màu {config.MAX_STYLED_ROWS:,} dòng đầu' if len(view) > config.MAX_STYLED_ROWS else ''))
    shown = view.head(config.MAX_STYLED_ROWS)
    st.dataframe(_style_rows(shown) if len(shown) else shown, width='stretch', height=380)
    st.download_button('Tải kết quả (CSV)', table.to_csv(index=False).encode('utf-8-sig'),
                       file_name=f'nids_ket_qua_{pred.model_name.replace(" ", "_")}_{pred.task}.csv',
                       mime='text/csv', key=f'{key}_dl')

    if y_true is not None:
        show_evaluation(y_true, pred, key)


def show_evaluation(y_true, pred, key):
    m = evaluate(y_true, pred)
    st.subheader('Đánh giá với nhãn thật trong file')
    c = st.columns(4)
    c[0].metric('Accuracy', f'{m["accuracy"]:.4f}')
    c[1].metric('F1-macro', f'{m["f1_macro"]:.4f}')
    c[2].metric('DR (tỉ lệ phát hiện)', f'{m["dr"]:.4f}')
    c[3].metric('FAR (báo động nhầm)', f'{m["far"]:.4f}')
    if 'Other' in m['labels']:
        st.warning('Có nhãn thật không thuộc các lớp mô hình đã học (hiển thị là "Other" hoặc tên gốc).')
    a, b = st.columns([3, 2])
    a.plotly_chart(plot_confusion(m['cm'], m['labels'], f'Confusion matrix – {pred.model_name}'),
                   width='stretch', key=f'{key}_cm')
    b.write('Classification report')
    b.dataframe(m['report'], width='stretch', height=420)
