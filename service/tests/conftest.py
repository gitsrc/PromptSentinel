# -*- coding: utf-8 -*-
"""pytest 引导:确保从 service/ 根目录可 import app/redteam/benchmark。"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
