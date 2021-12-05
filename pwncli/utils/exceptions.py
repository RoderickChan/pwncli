#!/usr/bin/env python3
# -*- encoding: utf-8 -*-
'''
@File    : exceptions.py
@Time    : 2021/11/23 23:47:51
@Author  : Roderick Chan
@Email   : ch22166@163.com
@Desc    : Exception
'''



__all__ = ["PwncliExit"]
class PwncliExit(SystemExit):
    """
    PwncliExit
    """
    pass

class PwncliTodoException(Exception):
    """
    TODO Exception
    """
    pass