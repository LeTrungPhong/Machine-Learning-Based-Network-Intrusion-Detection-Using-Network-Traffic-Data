# -*- coding: utf-8 -*-
"""Giao diện chung cho mọi nguồn luồng mạng."""
from abc import ABC, abstractmethod

import pandas as pd


class SourceUnavailable(RuntimeError):
    """Nguồn chưa sẵn sàng (thiếu backend, thiếu thư mục...). `help_md` chứa hướng dẫn khắc phục."""

    def __init__(self, message, help_md=''):
        super().__init__(message)
        self.help_md = help_md


class FlowSource(ABC):
    """Mọi nguồn đều trả về DataFrame luồng mạng với tên cột kiểu CICFlowMeter (bất kỳ phiên bản nào);
    core.schema.align_features sẽ ánh xạ về tên cột lúc huấn luyện."""

    name = 'base'

    @abstractmethod
    def get_flows(self) -> pd.DataFrame:
        """Trả về các luồng (mới) dưới dạng DataFrame."""
